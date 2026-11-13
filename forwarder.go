package main

// ATAK_FORWARDER (port 257): every other CoT from the mesh – markers, drawings, routes, deletions – as the ATAK
// Meshtastic plugin and TAKweb send it: the CoT XML zlib-compressed, below ~233 bytes as one packet, larger as
// "fountain" blocks (an LT code whose blocks are chosen with java.util.Random from a seed; same as the plugin's
// util/fountain and TAKweb's meshproto.js). Complete transfers are acknowledged into the mesh (like the plugin), so
// the sender stops repeating. What TAKweb gateways passed down from a TAK server (<__takwebmesh/>) is not taken again.

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/sha256"
	"io"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	ftnBlock    = 214
	ftnHeader   = 11
	ftnAckSize  = 19
	ftnComplete = 2
	portForward = 257
)

type javaRandom struct{ s int64 }

const jrMask = (int64(1) << 48) - 1

func newJavaRandom(seed int64) *javaRandom { return &javaRandom{s: (seed ^ 0x5DEECE66D) & jrMask} }
func (r *javaRandom) next(bits uint) int32 {
	r.s = (r.s*0x5DEECE66D + 0xB) & jrMask
	return int32(r.s >> (48 - bits))
}
func (r *javaRandom) nextDouble() float64 {
	return float64(int64(r.next(26))<<27+int64(r.next(27))) / float64(int64(1)<<53)
}
func (r *javaRandom) nextInt(bound int32) int32 {
	if bound&-bound == bound {
		return int32((int64(bound) * int64(r.next(31))) >> 31)
	}
	for {
		bits := r.next(31)
		val := bits % bound
		if bits-val+(bound-1) >= 0 {
			return val
		}
	}
}

// robust soliton distribution (c = 0.1, delta = 0.5 like the plugin)
func solitonCdf(K int) []float64 {
	c, delta := 0.1, 0.5
	mu, cdf := make([]float64, K+1), make([]float64, K+1)
	S := c * math.Log(float64(K)/delta) * math.Sqrt(float64(K))
	threshold := int(math.Floor(float64(K) / S))
	Z := 0.0
	for d := 1; d <= K; d++ {
		rho := 1 / (float64(d) * float64(d-1))
		if d == 1 {
			rho = 1 / float64(K)
		}
		tau := 0.0
		if d < threshold {
			tau = S / (float64(K) * float64(d))
		} else if d == threshold {
			tau = S * math.Log(S/delta) / float64(K)
		}
		mu[d] = rho + tau
		Z += mu[d]
	}
	cum := 0.0
	for d := 1; d <= K; d++ {
		cum += mu[d] / Z
		cdf[d] = cum
	}
	return cdf
}

func fountainIndices(seed, K, transferID int) []int {
	rng := newJavaRandom(int64(seed))
	cdf, u := solitonCdf(K), rng.nextDouble()
	deg := K
	for d := 1; d <= K; d++ {
		if u <= cdf[d] {
			deg = d
			break
		}
	}
	if seed == int(int32(uint32(transferID)*31337))&0xffff {
		deg = 1
	}
	if deg > K {
		deg = K
	}
	set := map[int]bool{}
	for len(set) < deg {
		set[int(rng.nextInt(int32(K)))] = true
	}
	out := make([]int, 0, len(set))
	for i := range set {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

type ftnBlockData struct {
	seed    int
	payload []byte
}

// fountainDecode: peeling decoder; nil while not decodable yet
func fountainDecode(blocks []ftnBlockData, K, total, transferID int) []byte {
	decoded := make([][]byte, K)
	count := 0
	type work struct {
		p   []byte
		idx map[int]bool
	}
	ws := make([]*work, 0, len(blocks))
	for _, b := range blocks {
		w := &work{p: append([]byte(nil), b.payload...), idx: map[int]bool{}}
		for _, i := range fountainIndices(b.seed, K, transferID) {
			w.idx[i] = true
		}
		ws = append(ws, w)
	}
	for progress := true; progress && count < K; {
		progress = false
		for _, w := range ws {
			if w.idx == nil {
				continue
			}
			for i := range w.idx {
				if decoded[i] == nil {
					continue
				}
				for j := range w.p {
					if j < len(decoded[i]) {
						w.p[j] ^= decoded[i][j]
					}
				}
				delete(w.idx, i)
			}
			if len(w.idx) == 1 {
				for i := range w.idx {
					decoded[i] = w.p
				}
				count++
				w.idx = nil
				progress = true
			} else if len(w.idx) == 0 {
				w.idx = nil
			}
		}
	}
	if count < K {
		return nil
	}
	out := make([]byte, 0, total)
	for i := 0; i < K; i++ {
		n := ftnBlock
		if rest := total - i*ftnBlock; rest < n {
			n = rest
		}
		if n > len(decoded[i]) {
			n = len(decoded[i])
		}
		out = append(out, decoded[i][:n]...)
	}
	return out
}

func unzlib(b []byte) []byte {
	if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		if out, err := io.ReadAll(io.LimitReader(r, 1<<20)); err == nil {
			return out
		}
	}
	if out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(b)), 1<<20)); err == nil && len(out) > 0 {
		return out
	}
	return b
}

type ftnTransfer struct {
	K, total int
	blocks   []ftnBlockData
	seeds    map[int]bool
	done     bool
	at       time.Time
}

// forwarder: a port 257 payload from a radio -> the CoT, once complete (nil otherwise)
func (m *Meshtastic) forwarder(p *meshPacket) []byte {
	b := p.Payload
	if len(b) >= 3 && b[0] == 'F' && b[1] == 'T' && b[2] == 'N' {
		if len(b) == ftnAckSize || len(b) < ftnHeader {
			return nil // acknowledgement of someone else's transfer
		}
		tid := int(b[3])<<16 | int(b[4])<<8 | int(b[5])
		seed, K, total := int(b[6])<<8|int(b[7]), int(b[8]), int(b[9])<<8|int(b[10])
		if K == 0 || K > 60 || total == 0 {
			return nil
		}
		key := uint64(p.From)<<32 | uint64(tid)
		m.mu.Lock()
		if m.transfers == nil {
			m.transfers = map[uint64]*ftnTransfer{}
		}
		for k, t := range m.transfers {
			if time.Since(t.at) > 10*time.Minute {
				delete(m.transfers, k)
			}
		}
		st := m.transfers[key]
		if st == nil || st.K != K || st.total != total {
			st = &ftnTransfer{K: K, total: total, seeds: map[int]bool{}}
			m.transfers[key] = st
		}
		st.at = time.Now()
		if st.done || st.seeds[seed] {
			m.mu.Unlock()
			return nil
		}
		st.seeds[seed] = true
		st.blocks = append(st.blocks, ftnBlockData{seed: seed, payload: append([]byte(nil), b[ftnHeader:]...)})
		var data []byte
		if len(st.blocks) >= K {
			data = fountainDecode(st.blocks, K, total, tid)
		}
		if data != nil {
			st.done = true
		}
		n := len(st.blocks)
		m.mu.Unlock()
		if data == nil {
			return nil
		}
		// acknowledge like the plugin, so the sender stops
		h := sha256.Sum256(data)
		ack := []byte{'F', 'T', 'N', byte(tid >> 16), byte(tid >> 8), byte(tid), ftnComplete, byte(n >> 8), byte(n), 0, 0}
		ack = append(ack, h[:8]...)
		if k, ok := m.srv.meshKeys()[p.ChannelName]; ok && k.down {
			m.down.push(downMsg{topicChannel: p.ChannelName, port: portForward, payload: ack})
		}
		if data[0] != 0x00 && data[0] != 0x30 {
			return nil // not CoT (files …)
		}
		return unzlib(data[1:])
	}
	if len(b) > 0 && (b[0] == 0xc2 || bytes.HasPrefix(b, []byte("MFT"))) {
		return nil // codec2 voice, file transfer receipt
	}
	return unzlib(b)
}

// forwardedCoT: the CoT from port 257 ready for the TAK devices (nil = not taken)
func forwardedCoT(xmlBytes []byte, extra string) []byte {
	s := strings.TrimSpace(string(xmlBytes))
	if i := strings.Index(s, "<event"); i > 0 {
		s = s[i:]
	}
	if !strings.HasPrefix(s, "<event") || strings.Contains(s, "<__takwebmesh") || strings.Contains(s, "<__mqtt") {
		return nil // not CoT, or passed down from a TAK server by a TAKweb gateway
	}
	if _, err := ParseEvent([]byte(s)); err != nil {
		return nil
	}
	switch {
	case strings.Contains(s, "</detail>"):
		s = strings.Replace(s, "</detail>", extra+"</detail>", 1)
	case strings.Contains(s, "<detail/>"):
		s = strings.Replace(s, "<detail/>", "<detail>"+extra+"</detail>", 1)
	default:
		s = strings.Replace(s, "</event>", "<detail>"+extra+"</detail></event>", 1)
	}
	return []byte(s)
}
