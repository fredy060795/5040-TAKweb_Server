package main

// Downlink: TAK traffic from this server into the mesh over MQTT, so radios without a phone connection on the server
// side (field radios, TAKweb on a radio, the ATAK Meshtastic plugin) see the headquarters: group chat ("All Chat
// Rooms", also as plain text for the Meshtastic app), direct messages to a TAK user on the mesh, and the positions of
// the TAK users – sparingly, LoRa airtime is scarce: a user's position at most every 5 minutes, one packet every
// 3 seconds, a short queue (the oldest positions are dropped first). Only channels with downlink on.
// What came from the mesh (<__mqtt>, <__meshtastic>, TAKweb's <__takwebmesh>) never goes back.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"html"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	downPLIEvery  = 5 * time.Minute
	downQueueSize = 40
)

var downInterval = 3 * time.Second // one packet into the mesh every 3 s (shorter in tests)

type downMsg struct {
	topicChannel string
	payload      []byte // Data payload
	port         int
	to           uint32
	pli          string // uid for positions (replaced by a newer one, dropped first)
}

type Downlink struct {
	m       *Meshtastic
	mu      sync.Mutex
	queue   []downMsg
	lastPLI map[string]time.Time
	nextID  uint32
	wake    chan struct{}
}

// serverNode: the Meshtastic node number the server sends as (from its UID, stable)
func (m *Meshtastic) serverNode() uint32 {
	h := sha256.Sum256([]byte("webtak-mesh-" + m.srv.store.Config().ServerUID))
	n := binary.LittleEndian.Uint32(h[:4])
	if n == 0 || n == 0xffffffff {
		n = 0x7a4b0001
	}
	return n
}

func newDownlink(m *Meshtastic) *Downlink {
	d := &Downlink{m: m, lastPLI: map[string]time.Time{}, wake: make(chan struct{}, 1), nextID: uint32(time.Now().UnixNano())}
	return d
}

func (d *Downlink) run(stop <-chan struct{}) {
	t := time.NewTicker(downInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			d.sendOne()
		}
	}
}

func (d *Downlink) push(msg downMsg) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if msg.pli != "" { // a newer position replaces the waiting one
		for i, q := range d.queue {
			if q.pli == msg.pli && q.topicChannel == msg.topicChannel {
				d.queue[i] = msg
				return
			}
		}
	}
	if len(d.queue) >= downQueueSize {
		drop := 0
		for i, q := range d.queue {
			if q.pli != "" {
				drop = i
				break
			}
		}
		d.queue = append(d.queue[:drop], d.queue[drop+1:]...)
	}
	if msg.pli == "" { // chat before positions
		i := 0
		for i < len(d.queue) && d.queue[i].pli == "" {
			i++
		}
		d.queue = append(d.queue[:i], append([]downMsg{msg}, d.queue[i:]...)...)
		return
	}
	d.queue = append(d.queue, msg)
}

func (d *Downlink) sendOne() {
	d.mu.Lock()
	if len(d.queue) == 0 {
		d.mu.Unlock()
		return
	}
	msg := d.queue[0]
	d.queue = d.queue[1:]
	d.nextID++
	id := d.nextID
	d.mu.Unlock()
	d.m.publish(msg, id)
}

// Pending: messages waiting (for tests and the web UI)
func (d *Downlink) Pending() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queue)
}

// publish: encrypt for the channel and give it to every radio subscribed under each root topic seen for it
func (m *Meshtastic) publish(msg downMsg, id uint32) {
	k, ok := m.srv.meshKeys()[msg.topicChannel]
	if !ok || !k.down {
		return
	}
	from := m.serverNode()
	data := (&pbWriter{}).uint(1, uint64(msg.port)).bytes(2, msg.payload).b
	enc, err := meshCrypt(k.key, id, from, data)
	if err != nil {
		return
	}
	to := msg.to
	if to == 0 {
		to = 0xffffffff
	}
	mp := (&pbWriter{}).fixed32(1, from).fixed32(2, to).uint(3, uint64(k.hash)).bytes(5, enc).fixed32(6, id).
		uint(9, 3).bool(14, true).uint(15, 3).b // hop limit 3, via MQTT (gateways do not send it back up)
	gw := nodeID(from)
	env := (&pbWriter{}).bytes(1, mp).str(2, k.name).str(3, gw).b
	for _, root := range m.roots(k.name) {
		m.srv.broker.Deliver(root+"/2/e/"+k.name+"/"+gw, env, nil)
	}
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()
}

// roots: the root topics radios used for this channel ("opentakserver" if none seen yet)
func (m *Meshtastic) roots(channel string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for r := range m.rootsSeen[channel] {
		out = append(out, r)
	}
	if len(out) == 0 {
		out = []string{"opentakserver"}
	}
	return out
}

// takPacket: TAKPacket for the ATAK plugin / TAKweb
func takPacket(callsign, deviceUID string, team, role string, battery int, pli []byte, chat []byte) []byte {
	contact := (&pbWriter{}).str(1, callsign).str(2, deviceUID).b
	w := (&pbWriter{}).bytes(2, contact)
	if t, r := indexOf(meshTeams, team, 0), indexOf(meshRoles, role, 0); t > 0 || r > 0 {
		w.bytes(3, (&pbWriter{}).uint(1, uint64(r)).uint(2, uint64(t)).b)
	}
	if battery > 0 {
		w.bytes(4, (&pbWriter{}).uint(1, uint64(battery)).b)
	}
	return w.bytes(5, pli).bytes(6, chat).b
}

var (
	reBattery = regexp.MustCompile(`<status\b[^>]*\sbattery="([^"]*)"`)
	reCourse  = regexp.MustCompile(`<track\b[^>]*\scourse="([^"]*)"`)
	reSpeed   = regexp.MustCompile(`<track\b[^>]*\sspeed="([^"]*)"`)
	reRemarks = regexp.MustCompile(`<remarks[^>]*>([^<]*)</remarks>`)
	reChatTo  = regexp.MustCompile(`<__chat\b[^>]*\sid="([^"]*)"`)
	reMsgID   = regexp.MustCompile(`<__chat\b[^>]*\smessageId="([^"]*)"`)
	reSender  = regexp.MustCompile(`<__chat\b[^>]*\ssenderCallsign="([^"]*)"`)
)

func sub1(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func xmlUnescape(s string) string { return html.UnescapeString(s) }

// Downlink: an event that came from a TAK device, a federated server or the web UI
func (m *Meshtastic) Downlink(raw []byte, ev *Event) {
	if m.down == nil {
		return
	}
	s := string(raw)
	if strings.Contains(s, "<__mqtt") || strings.Contains(s, "<__meshtastic") || strings.Contains(s, "<__takwebmesh") {
		return // came from the mesh
	}
	var chans []string
	for name, k := range m.srv.meshKeys() {
		if k.down {
			chans = append(chans, name)
		}
	}
	if len(chans) == 0 {
		return
	}
	switch {
	case ev.Type == "b-t-f":
		text := xmlUnescape(sub1(reRemarks, s))
		to := xmlUnescape(sub1(reChatTo, s))
		if text == "" {
			return
		}
		sender := xmlUnescape(sub1(reSender, s))
		if sender == "" {
			sender = ev.Callsign()
		}
		senderUID := ""
		for _, l := range ev.Detail.Link {
			if l.Relation == "p-p" {
				senderUID = l.UID
			}
		}
		msgID := xmlUnescape(sub1(reMsgID, s))
		if to != allChat && m.nodeOfTak(to) == 0 {
			return // direct messages only to TAK users the server heard on the mesh
		}
		if len(text) > 200 {
			text = text[:200]
		}
		chat := (&pbWriter{}).str(1, text).str(2, to).b
		pkt := takPacket(sender, senderUID+"|"+msgID, "", "", 0, nil, chat)
		for _, c := range chans {
			m.down.push(downMsg{topicChannel: c, port: portATAK, payload: pkt})
			if to == allChat { // also for people with only the Meshtastic app
				m.down.push(downMsg{topicChannel: c, port: portText, payload: []byte(sender + ": " + text)})
			}
		}
	case ev.IsSA() && !strings.HasPrefix(ev.UID, "MESH-") && time.Now().Before(ev.StaleTime()):
		m.down.mu.Lock()
		last := m.down.lastPLI[ev.UID]
		if time.Since(last) < downPLIEvery {
			m.down.mu.Unlock()
			return
		}
		m.down.lastPLI[ev.UID] = time.Now()
		m.down.mu.Unlock()
		team, role := "", ""
		if g := ev.Detail.Group; g != nil {
			team, role = g.Name, g.Role
		}
		var alt int64
		fmt.Sscanf(ev.Point.Hae, "%d", &alt)
		if alt > 9000 || alt < -500 {
			alt = 0
		}
		course, speed := atof(sub1(reCourse, s)), atof(sub1(reSpeed, s))
		pli := (&pbWriter{}).fixed32(1, uint32(int32(ev.Point.Lat*1e7))).fixed32(2, uint32(int32(ev.Point.Lon*1e7))).
			uint(3, uint64(alt)).uint(4, uint64(speed)).uint(5, uint64(course)).b
		bat := int(atof(sub1(reBattery, s)))
		pkt := takPacket(ev.Callsign(), ev.UID, team, role, bat, pli, nil)
		for _, c := range chans {
			m.down.push(downMsg{topicChannel: c, port: portATAK, payload: pkt, pli: ev.UID})
		}
	}
}

// nodeOfTak: the radio a TAK user was last heard from (for direct messages)
func (m *Meshtastic) nodeOfTak(uid string) uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	for num, n := range m.nodes {
		if n.TakUID == uid {
			return num
		}
	}
	return 0
}
