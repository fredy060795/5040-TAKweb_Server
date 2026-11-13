package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
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
