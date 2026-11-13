package main

// Meshtastic over MQTT (like OpenTAKServer): radios with internet (e.g. an HQ gateway) send what they hear on the mesh
// to this server's MQTT broker (mqtt.go) on <root>/2/e/<channel>/!<gateway>. The packets are encrypted with the
// channel key; with the channels stored under Meshtastic (OTS API /api/meshtastic/channel) the server opens them and
// turns positions, node names, chat and TAK packets (ATAK plugin / TAKweb) into CoT for every connected device.
// The CoT carries <__mqtt gateway="!…" channel="…" hops="…"/> so tools (TAKweb's network view) can show which radio
// passed it on. Several gateways hearing the same packet: delivered once.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	portText      = 1
	portPosition  = 3
	portNodeInfo  = 4
	portATAK      = 72
	portTelemetry = 67
	allChat       = "All Chat Rooms"
)

var meshTeams = []string{"", "White", "Yellow", "Orange", "Magenta", "Red", "Maroon", "Purple", "Dark Blue", "Blue", "Cyan", "Teal", "Green", "Dark Green", "Brown"}
var meshRoles = []string{"", "Team Member", "Team Lead", "HQ", "Sniper", "Medic", "Forward Observer", "RTO", "K9"}

// Meshtastic's default key ("AQ==" = key 1); key n changes the last byte
var meshDefaultKey = []byte{0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01}

var meshPresets = []string{"LONG_FAST", "LONG_SLOW", "VERY_LONG_SLOW", "MEDIUM_SLOW", "MEDIUM_FAST", "SHORT_SLOW", "SHORT_FAST", "LONG_MODERATE", "SHORT_TURBO"}
var meshRegions = []string{"UNSET", "US", "EU_433", "EU_868", "CN", "JP", "ANZ", "KR", "TW", "RU", "IN", "NZ_865", "TH", "LORA_24", "UA_433", "UA_868", "MY_433", "MY_919", "SG_923", "PH_433", "PH_868", "PH_915", "ANZ_433", "KZ_433", "KZ_863", "NP_865", "BR_902"}

// ---------- protobuf (just what is needed) ----------

type pbField struct {
	num  int
	wt   int
	v    uint64 // varint / fixed
	data []byte // length-delimited
}

type pbMsg []pbField

func pbDecode(b []byte) (pbMsg, error) {
	var out pbMsg
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("protobuf: bad key")
		}
		b = b[n:]
		f := pbField{num: int(key >> 3), wt: int(key & 7)}
		switch f.wt {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("protobuf: bad varint")
			}
			f.v, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("protobuf: short fixed64")
			}
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errors.New("protobuf: bad length")
			}
			f.data, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("protobuf: short fixed32")
			}
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		default:
			return nil, fmt.Errorf("protobuf: wire type %d", f.wt)
		}
		out = append(out, f)
	}
	return out, nil
}

func (m pbMsg) get(num int) *pbField {
	for i := len(m) - 1; i >= 0; i-- { // last one wins, like protobuf
		if m[i].num == num {
			return &m[i]
		}
	}
	return nil
}
func (m pbMsg) has(num int) bool { return m.get(num) != nil }
func (m pbMsg) u(num int) uint64 {
	if f := m.get(num); f != nil {
		return f.v
	}
	return 0
}
func (m pbMsg) i32(num int) int32 { return int32(uint32(m.u(num))) }
func (m pbMsg) bytes(num int) []byte {
	if f := m.get(num); f != nil {
		return f.data
	}
	return nil
}
func (m pbMsg) str(num int) string { return string(m.bytes(num)) }
func (m pbMsg) sub(num int) pbMsg {
	b := m.bytes(num)
	if b == nil {
		return nil
	}
	s, err := pbDecode(b)
	if err != nil {
		return nil
	}
	return s
}
func (m pbMsg) float(num int) float32 { return math.Float32frombits(uint32(m.u(num))) }

type pbWriter struct{ b []byte }

func (w *pbWriter) key(num, wt int) { w.b = binary.AppendUvarint(w.b, uint64(num<<3|wt)) }
func (w *pbWriter) uint(num int, v uint64) *pbWriter {
	if v != 0 {
		w.key(num, 0)
		w.b = binary.AppendUvarint(w.b, v)
	}
	return w
}
func (w *pbWriter) bool(num int, v bool) *pbWriter {
	if v {
		w.uint(num, 1)
	}
	return w
}
func (w *pbWriter) fixed32(num int, v uint32) *pbWriter {
	if v != 0 {
		w.key(num, 5)
		w.b = binary.LittleEndian.AppendUint32(w.b, v)
	}
	return w
}
func (w *pbWriter) bytes(num int, v []byte) *pbWriter {
	if len(v) > 0 {
		w.key(num, 2)
		w.b = binary.AppendUvarint(w.b, uint64(len(v)))
		w.b = append(w.b, v...)
	}
	return w
}
func (w *pbWriter) str(num int, v string) *pbWriter { return w.bytes(num, []byte(v)) }

// ---------- channels: key, URL ----------

type meshKey struct {
	name string
	key  []byte // AES key; nil = not encrypted
	hash uint8
	down bool // downlink allowed: TAK traffic from the server goes into this channel
}

func meshExpandPSK(psk []byte) []byte {
	switch {
	case len(psk) == 0:
		return nil
	case len(psk) == 1:
		if psk[0] == 0 {
			return nil
		}
		k := append([]byte(nil), meshDefaultKey...)
		k[15] += psk[0] - 1
		return k
	case len(psk) < 16:
		return append(append([]byte(nil), psk...), make([]byte, 16-len(psk))...)
	case len(psk) < 32 && len(psk) != 16:
		return append(append([]byte(nil), psk...), make([]byte, 32-len(psk))...)
	}
	return psk
}

func xorHash(b []byte) uint8 {
	var h uint8
	for _, c := range b {
		h ^= c
	}
	return h
}

func newMeshKey(name string, psk []byte) meshKey {
	k := meshExpandPSK(psk)
	return meshKey{name: name, key: k, hash: xorHash([]byte(name)) ^ xorHash(k)}
}

// channel link https://meshtastic.org/e/#<base64url ChannelSet> -> the channels (name + PSK) in it
func parseChannelURL(u string) (names []string, psks [][]byte, lora pbMsg, err error) {
	names, psks, _, lora, err = parseChannelLink(u)
	return
}

// parseChannelLink: like parseChannelURL, with the downlink flag of each channel
func parseChannelLink(u string) (names []string, psks [][]byte, downs []bool, lora pbMsg, err error) {
	i := strings.Index(u, "#")
	if i < 0 {
		return nil, nil, nil, nil, errors.New("no # in the channel link")
	}
	frag := u[i+1:]
	if j := strings.Index(frag, "?"); j >= 0 {
		frag = frag[:j]
	}
	if s, e := url.QueryUnescape(frag); e == nil {
		frag = s
	}
	frag = strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(frag), "=")
	raw, err := base64.RawStdEncoding.DecodeString(frag)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("channel link: %w", err)
	}
	set, err := pbDecode(raw)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	lora = set.sub(2)
	for _, f := range set {
		if f.num != 1 || f.wt != 2 {
			continue
		}
		cs, err := pbDecode(f.data)
		if err != nil {
			continue
		}
		names = append(names, cs.str(3))
		psks = append(psks, cs.bytes(2))
		downs = append(downs, cs.u(6) != 0)
	}
	return names, psks, downs, lora, nil
}

// presetName: the channel name Meshtastic uses for an empty name (the modem preset, e.g. "LongFast")
func presetName(preset int) string {
	n := "LONG_FAST"
	if preset >= 0 && preset < len(meshPresets) {
		n = meshPresets[preset]
	}
	parts := strings.Split(strings.ToLower(n), "_")
	for i, p := range parts {
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

func indexOf(list []string, v string, def int) int {
	for i, x := range list {
		if strings.EqualFold(x, v) {
			return i
		}
	}
	return def
}

// channelURL: link for a channel created by name (like OTS), so radios can be set to it
func channelURL(name string, psk []byte, preset, region string, uplink, downlink bool, hops int, precision int) string {
	mod := (&pbWriter{}).uint(1, uint64(precision)).b
	cs := (&pbWriter{}).bytes(2, psk).str(3, name).bool(5, uplink).bool(6, downlink).bytes(7, mod).b
	if hops <= 0 {
		hops = 3
	}
	lora := (&pbWriter{}).bool(1, true).uint(2, uint64(indexOf(meshPresets, preset, 0))).uint(7, uint64(indexOf(meshRegions, region, 3))).
		uint(8, uint64(hops)).bool(9, true).b
	set := (&pbWriter{}).bytes(1, cs).bytes(2, lora).b
	return "https://meshtastic.org/e/#" + base64.RawURLEncoding.EncodeToString(set)
}

// meshKeys: all channel keys of the stored channels, by name
func (s *Server) meshKeys() map[string]meshKey {
	out := map[string]meshKey{}
	s.store.Read(func(st *State) {
		for _, c := range st.Mesh {
			if c.URL != "" {
				if names, psks, downs, lora, err := parseChannelLink(c.URL); err == nil {
					for i, n := range names {
						if n == "" {
							n = presetName(int(lora.u(2)))
						}
						k := newMeshKey(n, psks[i])
						k.down = downs[i]
						out[n] = k
					}
					continue
				}
			}
			if psk, err := base64.StdEncoding.DecodeString(c.PSK); err == nil && c.Name != "" {
				k := newMeshKey(c.Name, psk)
				var d map[string]any
				json.Unmarshal([]byte(c.Data), &d)
				k.down = d["downlink_enabled"] != false
				out[c.Name] = k
			}
		}
	})
	return out
}

// ---------- packets ----------

func meshNonce(id uint32, from uint32) []byte {
	n := make([]byte, 16)
	binary.LittleEndian.PutUint64(n, uint64(id))
	binary.LittleEndian.PutUint32(n[8:], from)
	return n
}

func meshCrypt(key []byte, id, from uint32, data []byte) ([]byte, error) {
	if key == nil {
		return data, nil
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCTR(b, meshNonce(id, from)).XORKeyStream(out, data)
	return out, nil
}

type meshPacket struct {
	From, To, ID uint32
	Channel      uint32
	HopStart     uint32
	HopLimit     uint32
	SNR          float32
	RSSI         int32
	Port         int
	Payload      []byte
	Gateway      string
	ChannelName  string
}

func nodeID(n uint32) string { return fmt.Sprintf("!%08x", n) }

// openEnvelope: ServiceEnvelope { packet = 1, channel_id = 2, gateway_id = 3 } -> decrypted packet
func openEnvelope(body []byte, keys map[string]meshKey) (*meshPacket, error) {
	env, err := pbDecode(body)
	if err != nil {
		return nil, err
	}
	mp := env.sub(1)
	if mp == nil {
		return nil, errors.New("no packet")
	}
	p := &meshPacket{
		From: uint32(mp.u(1)), To: uint32(mp.u(2)), Channel: uint32(mp.u(3)), ID: uint32(mp.u(6)), SNR: mp.float(8),
		HopLimit: uint32(mp.u(9)), RSSI: mp.i32(12), HopStart: uint32(mp.u(15)), Gateway: env.str(3), ChannelName: env.str(2),
	}
	data := mp.sub(4)
	if data == nil {
		enc := mp.bytes(5)
		if enc == nil {
			return nil, errors.New("empty packet")
		}
		k, ok := keys[p.ChannelName]
		if !ok {
			return nil, fmt.Errorf("channel %q unknown here", p.ChannelName)
		}
		plain, err := meshCrypt(k.key, p.ID, p.From, enc)
		if err != nil {
			return nil, err
		}
		if data, err = pbDecode(plain); err != nil || !data.has(1) {
			return nil, fmt.Errorf("channel %q: wrong key", p.ChannelName)
		}
	}
	p.Port, p.Payload = int(data.u(1)), data.bytes(2)
	return p, nil
}

// ---------- CoT ----------

type meshNode struct {
	Long, Short, HW string
	TakUID          string
	Battery         int
	Voltage         float32
	Lat, Lon        float64
	Alt             int32
	Heard           time.Time
	PosTime         time.Time
	Gateway         string  // radio that uplinked the last packet
	Hops            int     // hops of the last packet (-1 unknown)
	SNR             float32 // at the gateway (only for direct = 0 hops meaningful)
	RSSI            int32
	Packets         int64
}

type Meshtastic struct {
	srv   *Server
	mu    sync.Mutex
	nodes map[uint32]*meshNode
	seen  map[uint64]time.Time
	stats map[string]*GatewayStat

	down      *Downlink
	rootsSeen map[string]map[string]bool // channel -> root topics radios use
	sent      int64                      // packets sent into the mesh
	transfers map[uint64]*ftnTransfer    // fountain transfers being received (port 257)
}

type GatewayStat struct {
	Gateway  string    `json:"gateway"`
	Channel  string    `json:"channel"`
	Packets  int64     `json:"packets"`
	Last     time.Time `json:"last"`
	Username string    `json:"username"`
}

func NewMeshtastic(s *Server) *Meshtastic {
	m := &Meshtastic{srv: s, nodes: map[uint32]*meshNode{}, seen: map[uint64]time.Time{}, stats: map[string]*GatewayStat{}, rootsSeen: map[string]map[string]bool{}}
	m.down = newDownlink(m)
	return m
}

func meshDetail(p *meshPacket) string {
	hops := 0
	if p.HopStart >= p.HopLimit {
		hops = int(p.HopStart - p.HopLimit)
	}
	return fmt.Sprintf(`<__mqtt gateway="%s" channel="%s" hops="%d" snr="%.1f" rssi="%d"/>`, xmlEscape(p.Gateway), xmlEscape(p.ChannelName), hops, p.SNR, p.RSSI)
}

func cotEvent(uid, typ, how string, t time.Time, stale time.Duration, lat, lon float64, hae string, detail string) []byte {
	if hae == "" {
		hae = "9999999"
	}
	return []byte(fmt.Sprintf(`<event version="2.0" uid="%s" type="%s" how="%s" time="%s" start="%s" stale="%s"><point lat="%.7f" lon="%.7f" hae="%s" ce="9999999" le="9999999"/><detail>%s</detail></event>`,
		xmlEscape(uid), typ, how, cotTime(t), cotTime(t), cotTime(t.Add(stale)), lat, lon, hae, detail))
}

func chatEvent(senderUID, senderCallsign, msgID, text, toUID string, extra string) []byte {
	room, id := allChat, allChat
	if toUID != "" {
		room, id = senderCallsign, toUID
	}
	now := time.Now()
	d := fmt.Sprintf(`<__chat parent="RootContactGroup" groupOwner="false" messageId="%s" chatroom="%s" id="%s" senderCallsign="%s"><chatgrp uid0="%s" uid1="%s" id="%s"/></__chat>`,
		xmlEscape(msgID), xmlEscape(room), xmlEscape(id), xmlEscape(senderCallsign), xmlEscape(senderUID), xmlEscape(id), xmlEscape(id)) +
		fmt.Sprintf(`<link uid="%s" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.%s" to="%s" time="%s">%s</remarks>`,
			xmlEscape(senderUID), xmlEscape(senderUID), xmlEscape(id), cotTime(now), xmlEscape(text))
	if toUID != "" {
		d += fmt.Sprintf(`<marti><dest uid="%s"/></marti>`, xmlEscape(toUID))
	}
	return cotEvent(fmt.Sprintf("GeoChat.%s.%s.%s", senderUID, id, msgID), "b-t-f", "h-g-i-g-o", now, 24*time.Hour, 0, 0, "", d+extra)
}

// nodeName: team from a name suffix like the ATAK plugin ("Hans -5" = Red), without one Cyan
func nodeName(name string) (callsign, team string) {
	if i := strings.LastIndex(name, " -"); i > 0 {
		var n int
		if _, err := fmt.Sscanf(name[i+2:], "%d", &n); err == nil && fmt.Sprint(n) == name[i+2:] {
			if n == 0 {
				return name[:i], "White"
			}
			if n > 0 && n < len(meshTeams) {
				return name[:i], meshTeams[n]
			}
		}
	}
	return name, "Cyan"
}

// Handle: one MQTT message from a radio. Returns the CoT events made from it (already delivered).
func (m *Meshtastic) Handle(topic string, body []byte, username string) [][]byte {
	parts := strings.Split(topic, "/")
	if len(parts) < 4 || parts[len(parts)-3] != "e" || parts[len(parts)-4] != "2" || parts[len(parts)-2] == "PKI" {
		return nil // not an encrypted channel message (JSON, map reports, status, PKI …)
	}
	p, err := openEnvelope(body, m.srv.meshKeys())
	if err != nil {
		return nil
	}
	if p.Gateway == "" {
		p.Gateway = parts[len(parts)-1]
	}
	if p.ChannelName == "" {
		p.ChannelName = parts[len(parts)-2]
	}
	if p.From == m.serverNode() {
		return nil // our own downlink, heard again
	}
	m.mu.Lock()
	root := strings.Join(parts[:len(parts)-4], "/")
	if m.rootsSeen[p.ChannelName] == nil {
		m.rootsSeen[p.ChannelName] = map[string]bool{}
	}
	m.rootsSeen[p.ChannelName][root] = true
	gs := m.stats[p.Gateway]
	if gs == nil {
		gs = &GatewayStat{Gateway: p.Gateway}
		m.stats[p.Gateway] = gs
	}
	gs.Packets++
	gs.Last, gs.Channel, gs.Username = time.Now(), p.ChannelName, username
	key := uint64(p.From)<<32 | uint64(p.ID)
	now := time.Now()
	for k, t := range m.seen {
		if now.Sub(t) > 10*time.Minute {
			delete(m.seen, k)
		}
	}
	if _, dup := m.seen[key]; dup && p.ID != 0 {
		m.mu.Unlock()
		return nil // another gateway was faster
	}
	m.seen[key] = now
	n := m.nodes[p.From]
	if n == nil {
		n = &meshNode{Battery: -1}
		m.nodes[p.From] = n
	}
	n.Heard = now
	n.Packets++
	n.Gateway, n.SNR, n.RSSI, n.Hops = p.Gateway, p.SNR, p.RSSI, -1
	if p.HopStart >= p.HopLimit && p.HopStart > 0 {
		n.Hops = int(p.HopStart - p.HopLimit)
	}
	m.mu.Unlock()

	var out [][]byte
	extra := meshDetail(p)
	id := nodeID(p.From)
	switch p.Port {
	case portNodeInfo:
		u, err := pbDecode(p.Payload)
		if err != nil {
			return nil
		}
		m.mu.Lock()
		n.Long, n.Short = u.str(2), u.str(3)
		if hw := int(u.u(5)); hw > 0 {
			n.HW = fmt.Sprint(hw)
		}
		has := n.Lat != 0 || n.Lon != 0
		m.mu.Unlock()
		if has && n.TakUID == "" {
			out = append(out, m.nodeCoT(p.From, n, extra))
		}
	case portPosition:
		pos, err := pbDecode(p.Payload)
		if err != nil || !pos.has(1) || !pos.has(2) {
			return nil
		}
		m.mu.Lock()
		n.Lat, n.Lon, n.Alt = float64(int32(uint32(pos.u(1))))/1e7, float64(int32(uint32(pos.u(2))))/1e7, pos.i32(3)
		n.PosTime = now
		tak := n.TakUID
		m.mu.Unlock()
		if (n.Lat != 0 || n.Lon != 0) && tak == "" {
			out = append(out, m.nodeCoT(p.From, n, extra))
		}
	case portText:
		if p.To != 0xffffffff {
			return nil // direct message between radios
		}
		m.mu.Lock()
		name, tak := n.Long, n.TakUID
		m.mu.Unlock()
		if tak != "" {
			return nil // TAK users send chat as a TAK packet too
		}
		if name == "" {
			name = id
		}
		cs, _ := nodeName(name)
		out = append(out, chatEvent("MESH-"+id, cs, fmt.Sprint(p.ID), string(p.Payload), "", extra))
	case portATAK:
		tp, err := pbDecode(p.Payload)
		if err != nil || tp.u(1) != 0 {
			return nil // compressed (old plugin versions) – not readable here
		}
		c, g, st, pli, chat := tp.sub(2), tp.sub(3), tp.sub(4), tp.sub(5), tp.sub(6)
		callsign, devUID := c.str(1), c.str(2)
		uid, msgID := devUID, ""
		if i := strings.Index(devUID, "|"); i >= 0 {
			uid, msgID = devUID[:i], devUID[i+1:]
		}
		if uid == "" {
			uid = "MESH-" + id
		}
		if callsign == "" {
			callsign = id
		}
		m.mu.Lock()
		n.TakUID = uid
		m.mu.Unlock()
		if pli != nil {
			team, role := "Cyan", "Team Member"
			if g != nil {
				if t := int(g.u(2)); t > 0 && t < len(meshTeams) {
					team = meshTeams[t]
				}
				if r := int(g.u(1)); r > 0 && r < len(meshRoles) {
					role = meshRoles[r]
				}
			}
			d := fmt.Sprintf(`<contact callsign="%s" endpoint="MQTT"/><__group name="%s" role="%s"/>`, xmlEscape(callsign), team, role)
			if st != nil && st.has(1) {
				d += fmt.Sprintf(`<status battery="%d"/>`, st.u(1))
			}
			d += fmt.Sprintf(`<track course="%d" speed="%d"/><takv platform="Meshtastic" device="Mesh" meshtastic_id="%08x"/><__meshtastic/>`, pli.u(5), pli.u(4), p.From)
			hae := ""
			if a := pli.i32(3); a != 0 {
				hae = fmt.Sprint(a)
			}
			lat, lon := float64(int32(uint32(pli.u(1))))/1e7, float64(int32(uint32(pli.u(2))))/1e7
			out = append(out, cotEvent(uid, "a-f-G-U-C", "m-g", time.Now(), 10*time.Minute, lat, lon, hae, d+extra))
		} else if chat != nil && chat.str(2) != "" {
			to := chat.str(2)
			if msgID == "" {
				msgID = fmt.Sprint(p.ID)
			}
			if to == allChat {
				to = ""
			}
			out = append(out, chatEvent(uid, callsign, msgID, chat.str(1), to, extra))
		}
	case portTelemetry:
		tm, err := pbDecode(p.Payload)
		if err != nil {
			return nil
		}
		if dm := tm.sub(2); dm != nil {
			m.mu.Lock()
			if dm.has(1) {
				n.Battery = int(dm.u(1))
			}
			if dm.has(2) {
				n.Voltage = dm.float(2)
			}
			m.mu.Unlock()
		}
		return nil
	case portForward:
		if xml := m.forwarder(p); xml != nil {
			if raw := forwardedCoT(xml, extra); raw != nil {
				out = append(out, raw)
			}
		}
	default:
		return nil
	}
	for _, raw := range out {
		m.srv.hub.FromMesh(raw)
	}
	return out
}

func (m *Meshtastic) nodeCoT(num uint32, n *meshNode, extra string) []byte {
	name := n.Long
	if name == "" {
		name = n.Short
	}
	if name == "" {
		name = nodeID(num)
	}
	cs, team := nodeName(name)
	hae := ""
	if n.Alt != 0 {
		hae = fmt.Sprint(n.Alt)
	}
	d := fmt.Sprintf(`<contact callsign="%s" endpoint="MQTT"/><__group name="%s" role="Team Member"/><takv platform="Meshtastic" device="%s" meshtastic_id="%08x"/><remarks>Meshtastic %s</remarks><__meshtastic/>`,
		xmlEscape(cs), team, xmlEscape(n.HW), num, nodeID(num))
	return cotEvent("MESH-"+nodeID(num), "a-f-G-E-S", "m-g", time.Now(), 30*time.Minute, n.Lat, n.Lon, hae, d+extra)
}

// Status: gateways, connected radios, every node heard over MQTT – for the web UI and tools (TAKweb's network view)
func (m *Meshtastic) Status() map[string]any {
	keys := m.srv.meshKeys()
	var chans []map[string]any
	for name, k := range keys {
		chans = append(chans, map[string]any{"name": name, "downlink": k.down, "encrypted": k.key != nil})
	}
	m.mu.Lock()
	var nodes []map[string]any
	for num, n := range m.nodes {
		item := map[string]any{"id": nodeID(num), "longName": n.Long, "shortName": n.Short, "takUid": n.TakUID, "heard": n.Heard,
			"gateway": n.Gateway, "hops": n.Hops, "snr": n.SNR, "rssi": n.RSSI, "packets": n.Packets}
		if n.Lat != 0 || n.Lon != 0 {
			item["lat"], item["lon"], item["positionTime"] = n.Lat, n.Lon, n.PosTime
		}
		if n.Battery >= 0 {
			item["battery"] = n.Battery
		}
		if n.Voltage > 0 {
			item["voltage"] = n.Voltage
		}
		nodes = append(nodes, item)
	}
	sent := m.sent
	m.mu.Unlock()
	return map[string]any{"gateways": m.Gateways(), "clients": m.srv.broker.Clients(), "nodes": nodes, "channels": chans,
		"downlinkSent": sent, "downlinkPending": m.down.Pending(), "serverNode": nodeID(m.serverNode()),
		"port": m.srv.ports.MQTT, "plainPort": m.srv.ports.MQTTPlain}
}

// Gateways: radios that sent to the broker (for the web UI and tools)
func (m *Meshtastic) Gateways() []GatewayStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []GatewayStat
	for _, g := range m.stats {
		out = append(out, *g)
	}
	return out
}
