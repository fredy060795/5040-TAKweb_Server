package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------- a Meshtastic radio as MQTT client ----------

type testRadio struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

func dialMQTT(t *testing.T, port int, user, pw, clientID string) (*testRadio, byte) {
	t.Helper()
	c, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{InsecureSkipVerify: true}) // radios do not check
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	body := appendString(nil, "MQTT")
	body = append(body, 4, 0xC2, 0, 60) // level 4, user+password+clean session, keep-alive 60 s
	body = appendString(body, clientID)
	body = appendString(body, user)
	body = appendString(body, pw)
	c.Write(mqttPacket(mqttConnect, 0, body))
	tr := &testRadio{t: t, conn: c, r: bufio.NewReader(c)}
	typ, _, b := tr.read()
	if typ != mqttConnack || len(b) != 2 {
		t.Fatalf("no CONNACK: %d", typ)
	}
	return tr, b[1]
}

func (tr *testRadio) read() (byte, byte, []byte) {
	tr.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, flags, body, err := readMQTT(tr.r)
	if err != nil {
		tr.t.Fatalf("MQTT read: %v", err)
	}
	return typ, flags, body
}

func (tr *testRadio) subscribe(filter string) {
	body := append([]byte{0, 1}, appendString(nil, filter)...)
	tr.conn.Write(mqttPacket(mqttSubscribe, 2, append(body, 0)))
	if typ, _, _ := tr.read(); typ != mqttSuback {
		tr.t.Fatal("no SUBACK")
	}
}

func (tr *testRadio) publish(topic string, payload []byte) {
	tr.conn.Write(mqttPacket(mqttPublish, 0, append(appendString(nil, topic), payload...)))
}

// envelope: what a gateway radio publishes – ServiceEnvelope with the encrypted packet
func envelope(t *testing.T, key meshKey, from, id uint32, port int, payload []byte, gw string) []byte {
	data := (&pbWriter{}).uint(1, uint64(port)).bytes(2, payload).b
	enc, err := meshCrypt(key.key, id, from, data)
	if err != nil {
		t.Fatal(err)
	}
	mp := (&pbWriter{}).fixed32(1, from).fixed32(2, 0xffffffff).uint(3, uint64(key.hash)).bytes(5, enc).fixed32(6, id).uint(9, 1).uint(15, 3).b
	return (&pbWriter{}).bytes(1, mp).str(2, key.name).str(3, gw).b
}

func sfixed(v float64) uint32 { return uint32(int32(v * 1e7)) }

func takPLI(uid, callsign string, lat, lon float64) []byte {
	contact := (&pbWriter{}).str(1, callsign).str(2, uid).b
	group := (&pbWriter{}).uint(1, 2).uint(2, 5).b // Team Lead, Red
	status := (&pbWriter{}).uint(1, 80).b
	pli := (&pbWriter{}).fixed32(1, sfixed(lat)).fixed32(2, sfixed(lon)).uint(3, 520).uint(4, 3).uint(5, 90).b
	return (&pbWriter{}).bytes(2, contact).bytes(3, group).bytes(4, status).bytes(5, pli).b
}

func TestMeshChannelLinkAndCrypto(t *testing.T) {
	link := channelURL("TAK", bytes.Repeat([]byte{7}, 32), "LONG_FAST", "EU_868", true, false, 3, 32)
	names, psks, lora, err := parseChannelURL(link)
	if err != nil || len(names) != 1 || names[0] != "TAK" || len(psks[0]) != 32 || lora.u(7) != 3 {
		t.Fatalf("link: %v %v %v", names, err, lora)
	}
	if k := newMeshKey("LongFast", []byte{1}); !bytes.Equal(k.key, meshDefaultKey) || k.hash != 8 {
		t.Fatalf("default key: %x hash %d", k.key, k.hash) // LongFast with the default key: channel hash 8 like in Meshtastic
	}
	if presetName(0) != "LongFast" || presetName(4) != "MediumFast" {
		t.Fatal(presetName(4))
	}
	k := newMeshKey("TAK", psks[0])
	env := envelope(t, k, 0x11223344, 77, portText, []byte("hello"), "!aabbccdd")
	p, err := openEnvelope(env, map[string]meshKey{"TAK": k})
	if err != nil || string(p.Payload) != "hello" || p.Port != portText || p.Gateway != "!aabbccdd" || p.HopStart-p.HopLimit != 2 {
		t.Fatalf("open: %+v %v", p, err)
	}
	if _, err := openEnvelope(env, map[string]meshKey{"TAK": newMeshKey("TAK", []byte{1})}); err == nil {
		t.Fatal("opened with the wrong key")
	}
	if !topicMatch("opentakserver/2/e/TAK/+", "opentakserver/2/e/TAK/!aabbccdd") || topicMatch("opentakserver/2/e/TAK/+", "opentakserver/2/e/X/!a") || !topicMatch("msh/#", "msh/EU_868/2/e/x/y") {
		t.Fatal("topic match")
	}
}

func TestMQTTMeshtasticToTAK(t *testing.T) {
	srv := startServer(t, "A")
	srv.CreateUser("radio", "radio-pass-1", false, nil)
	link := channelURL("TAK", bytes.Repeat([]byte{9}, 32), "LONG_FAST", "EU_868", true, true, 3, 32)
	srv.store.Update(func(s *State) { s.Mesh = append(s.Mesh, &MeshChannel{ID: 1, URL: link}) })
	key := srv.meshKeys()["TAK"]

	if _, code := dialMQTT(t, srv.ports.MQTT, "radio", "wrong", "!0bad0bad"); code != 4 {
		t.Fatalf("wrong password accepted: %d", code)
	}
	gw1, code := dialMQTT(t, srv.ports.MQTT, "radio", "radio-pass-1", "!00000001")
	if code != 0 {
		t.Fatal("login")
	}
	gw2, _ := dialMQTT(t, srv.ports.MQTT, "radio", "radio-pass-1", "!00000002")
	gw2.subscribe("opentakserver/2/e/TAK/+")

	dev := dialTCP(t, srv.ports.TCP)
	dev.send(sa("ATAK-HQ", "HQ"))
	time.Sleep(200 * time.Millisecond)

	// a TAK user (ATAK plugin / TAKweb) heard by gateway 1 – and the same packet by gateway 3 a bit later
	env := envelope(t, key, 0x0a0b0c0d, 1001, portATAK, takPLI("ANDROID-77", "Bravo", 47.26, 11.39), "!00000001")
	gw1.publish("opentakserver/2/e/TAK/!00000001", env)
	ev, raw := dev.waitFor("mesh PLI", uidIs("ANDROID-77"))
	if ev.Callsign() != "Bravo" || ev.Detail.Group.Name != "Red" || ev.Detail.Group.Role != "Team Lead" || ev.Point.Lat < 47.25 {
		t.Fatalf("PLI: %s", raw)
	}
	for _, want := range []string{`gateway="!00000001"`, `channel="TAK"`, `hops="2"`, `platform="Meshtastic"`, `meshtastic_id="0a0b0c0d"`, `endpoint="MQTT"`, `battery="80"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %s in %s", want, raw)
		}
	}
	// the other radio got the message from the broker (meshes linked over the internet)
	if typ, _, body := gw2.read(); typ != mqttPublish || !bytes.HasSuffix(body, env) {
		t.Fatal("not forwarded to the other radio")
	}
	gw3, _ := dialMQTT(t, srv.ports.MQTT, "radio", "radio-pass-1", "!00000003")
	gw3.publish("opentakserver/2/e/TAK/!00000003", envelope(t, key, 0x0a0b0c0d, 1001, portATAK, takPLI("ANDROID-77", "Bravo", 47.26, 11.39), "!00000003"))
	time.Sleep(300 * time.Millisecond)
	if n := dev.count(uidIs("ANDROID-77")); n != 1 {
		t.Fatalf("delivered %d times", n)
	}

	// a plain Meshtastic radio: name, then position -> contact MESH-!…
	user := (&pbWriter{}).str(1, "!0000beef").str(2, "Relay Hill -12").str(3, "RH").b
	gw1.publish("opentakserver/2/e/TAK/!00000001", envelope(t, key, 0xbeef, 2001, portNodeInfo, user, "!00000001"))
	pos := (&pbWriter{}).fixed32(1, sfixed(47.3)).fixed32(2, sfixed(11.4)).uint(3, 900).b
	gw1.publish("opentakserver/2/e/TAK/!00000001", envelope(t, key, 0xbeef, 2002, portPosition, pos, "!00000001"))
	ev, raw = dev.waitFor("mesh node", uidIs("MESH-!0000beef"))
	if ev.Callsign() != "Relay Hill" || ev.Detail.Group.Name != "Green" || !strings.Contains(string(raw), `type="a-f-G-E-S"`) {
		t.Fatalf("node: %s", raw)
	}

	// chat from a plain radio to everyone
	gw1.publish("opentakserver/2/e/TAK/!00000001", envelope(t, key, 0xbeef, 2003, portText, []byte("Bridge is out"), "!00000001"))
	_, raw = dev.waitFor("mesh chat", func(e *Event) bool { return e.Type == "b-t-f" })
	if !strings.Contains(string(raw), "Bridge is out") || !strings.Contains(string(raw), `senderCallsign="Relay Hill"`) || !strings.Contains(string(raw), allChat) {
		t.Fatalf("chat: %s", raw)
	}

	// unknown channel / other topics: ignored
	gw1.publish("opentakserver/2/e/OTHER/!00000001", envelope(t, newMeshKey("OTHER", []byte{1}), 5, 6, portText, []byte("x"), "!00000001"))
	gw1.publish("opentakserver/2/json/TAK/!00000001", []byte(`{}`))
	time.Sleep(200 * time.Millisecond)

	gws := srv.mesh.Gateways()
	if len(gws) != 2 { // gateway 2 only listened
		t.Fatalf("gateways: %+v", gws)
	}
	if len(srv.broker.Clients()) != 3 {
		t.Fatal("clients")
	}
	_ = binary.LittleEndian
}

// opens what the server sent into the mesh
func openDown(t *testing.T, body []byte, key meshKey) *meshPacket {
	t.Helper()
	p, err := openEnvelope(body, map[string]meshKey{key.name: key})
	if err != nil {
		t.Fatalf("downlink not readable: %v", err)
	}
	return p
}

func TestMeshDownlink(t *testing.T) {
	downInterval = 50 * time.Millisecond
	defer func() { downInterval = 3 * time.Second }()
	srv := startServer(t, "A")
	srv.CreateUser("radio", "radio-pass-1", false, nil)
	link := channelURL("TAK", bytes.Repeat([]byte{4}, 32), "LONG_FAST", "EU_868", true, true, 3, 32)
	noDown := channelURL("QUIET", bytes.Repeat([]byte{5}, 16), "LONG_FAST", "EU_868", true, false, 3, 32)
	srv.store.Update(func(s *State) {
		s.Mesh = append(s.Mesh, &MeshChannel{ID: 1, URL: link}, &MeshChannel{ID: 2, URL: noDown})
	})
	key := srv.meshKeys()["TAK"]
	gw, _ := dialMQTT(t, srv.ports.MQTT, "radio", "radio-pass-1", "!00000001")
	gw.subscribe("msh/EU/2/e/#")
	// the radio uses the root "msh/EU": the server learns it from what the radio sends
	gw.publish("msh/EU/2/e/TAK/!00000001", envelope(t, key, 0x0a0b0c0d, 1, portATAK, takPLI("ANDROID-77", "Bravo", 47.26, 11.39), "!00000001"))
	time.Sleep(200 * time.Millisecond)

	dev := dialTCP(t, srv.ports.TCP)
	dev.send(sa("ATAK-HQ", "HQ"))
	now := time.Now()
	dev.send(fmt.Sprintf(`<event version="2.0" uid="GeoChat.ATAK-HQ.All Chat Rooms.m1" type="b-t-f" how="h-g-i-g-o" time="%s" start="%s" stale="%s"><point lat="0" lon="0" hae="0" ce="9999999" le="9999999"/><detail><__chat parent="RootContactGroup" groupOwner="false" messageId="m1" chatroom="All Chat Rooms" id="All Chat Rooms" senderCallsign="HQ"><chatgrp uid0="ATAK-HQ" uid1="All Chat Rooms" id="All Chat Rooms"/></__chat><link uid="ATAK-HQ" type="a-f-G-U-C" relation="p-p"/><remarks source="BAO.F.ATAK.ATAK-HQ" to="All Chat Rooms" time="%s">Move to checkpoint 2</remarks></detail></event>`,
		cotTime(now), cotTime(now), cotTime(now.Add(time.Hour)), cotTime(now)))

	var gotChat, gotText, gotPLI bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(gotChat && gotText && gotPLI) {
		typ, _, body := gw.read()
		if typ != mqttPublish {
			continue
		}
		topic, payload, _ := mqttString(body)
		if !strings.HasPrefix(topic, "msh/EU/2/e/TAK/!") {
			t.Fatalf("topic %s", topic)
		}
		p := openDown(t, payload, key)
		if p.From != srv.mesh.serverNode() || p.To != 0xffffffff {
			t.Fatalf("from/to %x %x", p.From, p.To)
		}
		switch p.Port {
		case portText:
			gotText = string(p.Payload) == "HQ: Move to checkpoint 2"
		case portATAK:
			tp, _ := pbDecode(p.Payload)
			if ch := tp.sub(6); ch != nil {
				gotChat = ch.str(1) == "Move to checkpoint 2" && ch.str(2) == allChat && tp.sub(2).str(2) == "ATAK-HQ|m1"
			} else if pl := tp.sub(5); pl != nil {
				gotPLI = tp.sub(2).str(2) == "ATAK-HQ" && int32(uint32(pl.u(1))) == int32(48.1*1e7)
			}
		}
	}
	if !gotChat || !gotText || !gotPLI {
		t.Fatalf("downlink chat %v text %v position %v", gotChat, gotText, gotPLI)
	}
	// a position again right away: not sent (5 min), and what came from the mesh never goes back
	dev.send(sa("ATAK-HQ", "HQ"))
	time.Sleep(300 * time.Millisecond)
	if srv.mesh.down.Pending() != 0 {
		t.Fatal("position sent again too early")
	}
	srv.hub.FromMesh(cotEvent("MESH-!0000beef", "a-f-G-E-S", "m-g", time.Now(), time.Minute, 1, 1, "", `<contact callsign="x" endpoint="MQTT"/><takv platform="Meshtastic"/><__mqtt gateway="!1"/>`))
	if srv.mesh.down.Pending() != 0 {
		t.Fatal("mesh event went back down")
	}
	// own downlink heard again by a gateway: ignored
	if out := srv.mesh.Handle("msh/EU/2/e/TAK/!00000001", envelope(t, key, srv.mesh.serverNode(), 99, portText, []byte("x"), "!00000001"), "radio"); out != nil {
		t.Fatal("own packet handled")
	}
}

func TestForwarderFromTAKwebAndPlugin(t *testing.T) {
	var v struct {
		XML        string   `json:"xml"`
		K          int      `json:"K"`
		TransferID int      `json:"transferId"`
		Blocks     []string `json:"blocks"`
		Small      string   `json:"small"`
		Indices    [][]int  `json:"indices"`
	}
	b, err := os.ReadFile("testdata/fountain.json") // made with TAKweb's meshproto.js
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &v)
	for i, want := range v.Indices { // same block choice as java.util.Random in the plugin / TAKweb
		seed := int(int32(uint32(v.TransferID)*31337)+int32(i*7919)) & 0xffff
		if got := fountainIndices(seed, v.K, v.TransferID); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("block %d: %v, TAKweb %v", i, got, want)
		}
	}

	downInterval = 50 * time.Millisecond
	defer func() { downInterval = 3 * time.Second }()
	srv := startServer(t, "A")
	srv.CreateUser("radio", "radio-pass-1", false, nil)
	link := channelURL("TAK", bytes.Repeat([]byte{6}, 32), "LONG_FAST", "EU_868", true, true, 3, 32)
	srv.store.Update(func(s *State) { s.Mesh = append(s.Mesh, &MeshChannel{ID: 1, URL: link}) })
	key := srv.meshKeys()["TAK"]
	gw, _ := dialMQTT(t, srv.ports.MQTT, "radio", "radio-pass-1", "!00000001")
	gw.subscribe("opentakserver/2/e/TAK/+")
	dev := dialTCP(t, srv.ports.TCP)
	dev.send(sa("ATAK-HQ", "HQ"))
	time.Sleep(200 * time.Millisecond)
	// blocks arrive in a different order, the first one twice
	order := []int{1, 0, 0, 3, 2, 4, 5}
	for n, i := range order {
		if i >= len(v.Blocks) {
			continue
		}
		blk, _ := base64.StdEncoding.DecodeString(v.Blocks[i])
		gw.publish("opentakserver/2/e/TAK/!00000001", envelope(t, key, 0x77, uint32(500+n), portForward, blk, "!00000001"))
	}
	_, raw := dev.waitFor("marker from the mesh", uidIs("u-marker-1"))
	if !strings.Contains(string(raw), "Seen at the bridge") || !strings.Contains(string(raw), `gateway="!00000001"`) {
		t.Fatalf("marker: %s", raw)
	}
	// the sender gets the acknowledgement (so it stops repeating)
	gotAck := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) && !gotAck; {
		if typ, _, body := gw.read(); typ == mqttPublish {
			_, payload, _ := mqttString(body)
			p := openDown(t, payload, key)
			gotAck = p.Port == portForward && len(p.Payload) == ftnAckSize && p.Payload[6] == ftnComplete
		}
	}
	if !gotAck {
		t.Fatal("no fountain acknowledgement")
	}
	// a small one in one packet (deletion)
	small, _ := base64.StdEncoding.DecodeString(v.Small)
	gw.publish("opentakserver/2/e/TAK/!00000001", envelope(t, key, 0x77, 600, portForward, small, "!00000001"))
	dev.waitFor("deletion", uidIs("d1"))
	// passed down from a TAK server by a TAKweb gateway: not taken again
	if forwardedCoT([]byte(`<event uid="x" type="a-h-G"><point lat="1" lon="1"/><detail><__takwebmesh/></detail></event>`), "") != nil {
		t.Fatal("bridge copy taken")
	}
}
