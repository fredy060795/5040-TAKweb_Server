package main

// Small MQTT 3.1.1 broker for Meshtastic radios (port 8883 with TLS, optionally 1883 without): login with a user of
// this server, publish/subscribe with + and # wildcards, QoS 0 and 1 (delivered as QoS 0), keep-alive. No retained
// messages, no persistent sessions – a radio subscribes again after every connect.
// What radios publish on <root>/2/e/<channel>/!<gateway> goes to Meshtastic (meshtastic.go) and, like on every
// broker, to the other subscribed radios: radios at different places are linked over the internet.

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	mqttConnect     = 1
	mqttConnack     = 2
	mqttPublish     = 3
	mqttPuback      = 4
	mqttSubscribe   = 8
	mqttSuback      = 9
	mqttUnsubscribe = 10
	mqttUnsuback    = 11
	mqttPingreq     = 12
	mqttPingresp    = 13
	mqttDisconnect  = 14
	mqttMaxPacket   = 256 << 10
)

type mqttSession struct {
	conn     net.Conn
	clientID string
	username string
	remote   string
	mu       sync.Mutex
	subs     []string
	send     chan []byte
	closed   chan struct{}
	once     sync.Once
}

func (c *mqttSession) close() { c.once.Do(func() { close(c.closed); c.conn.Close() }) }

type Broker struct {
	srv       *Server
	mu        sync.RWMutex
	sessions  map[*mqttSession]bool
	onPublish func(topic string, payload []byte, username string)
}

func NewBroker(s *Server) *Broker { return &Broker{srv: s, sessions: map[*mqttSession]bool{}} }

// topicMatch: MQTT filter (with + and #) against a topic
func topicMatch(filter, topic string) bool {
	f, t := strings.Split(filter, "/"), strings.Split(topic, "/")
	for i, p := range f {
		if p == "#" {
			return true
		}
		if i >= len(t) {
			return false
		}
		if p != "+" && p != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

func mqttPacket(typ byte, flags byte, body []byte) []byte {
	out := []byte{typ<<4 | flags}
	l := len(body)
	for {
		b := byte(l % 128)
		l /= 128
		if l > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if l == 0 {
			break
		}
	}
	return append(out, body...)
}

func mqttString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, errors.New("short string")
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return "", nil, errors.New("short string")
	}
	return string(b[2 : 2+n]), b[2+n:], nil
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

func readMQTT(r *bufio.Reader) (typ, flags byte, body []byte, err error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	l, mul := 0, 1
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		l += int(b&0x7f) * mul
		mul *= 128
		if b&0x80 == 0 {
			break
		}
		if i == 3 {
			return 0, 0, nil, errors.New("bad length")
		}
	}
	if l > mqttMaxPacket {
		return 0, 0, nil, errors.New("packet too large")
	}
	body = make([]byte, l)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return h >> 4, h & 0x0f, body, nil
}

func (s *Server) tlsConfigMQTT() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.pki.WebCertificate}
}

func (s *Server) serveMQTT(l net.Listener, useTLS bool) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				if s.ctx.Err() != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if useTLS {
				conn = tls.Server(conn, s.tlsConfigMQTT())
			}
			go s.broker.handle(conn)
		}
	}()
}

func (b *Broker) handle(conn net.Conn) {
	c := &mqttSession{conn: conn, remote: conn.RemoteAddr().String(), send: make(chan []byte, 256), closed: make(chan struct{})}
	defer c.close()
	r := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	typ, _, body, err := readMQTT(r)
	if err != nil || typ != mqttConnect {
		return
	}
	keep, code := b.connect(c, body)
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(mqttPacket(mqttConnack, 0, []byte{0, code})); err != nil || code != 0 {
		if code != 0 {
			logf("MQTT login refused: %q from %s", c.username, c.remote)
		}
		return
	}
	b.mu.Lock()
	b.sessions[c] = true
	b.mu.Unlock()
	logf("MQTT: %s (%s) connected from %s", c.clientID, c.username, c.remote)
	defer func() {
		b.mu.Lock()
		delete(b.sessions, c)
		b.mu.Unlock()
		logf("MQTT: %s disconnected", c.clientID)
	}()
	go func() { // writer
		for {
			select {
			case p := <-c.send:
				conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
				if _, err := conn.Write(p); err != nil {
					c.close()
					return
				}
			case <-c.closed:
				return
			}
		}
	}()
	idle := 5 * time.Minute
	if keep > 0 {
		idle = time.Duration(keep) * 1500 * time.Millisecond
	}
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		typ, flags, body, err := readMQTT(r)
		if err != nil {
			return
		}
		switch typ {
		case mqttPublish:
			b.publish(c, flags, body)
		case mqttSubscribe:
			b.subscribe(c, body)
		case mqttUnsubscribe:
			b.unsubscribe(c, body)
		case mqttPingreq:
			c.queue(mqttPacket(mqttPingresp, 0, nil))
		case mqttDisconnect:
			return
		case mqttPuback:
		default:
			return
		}
	}
}

func (c *mqttSession) queue(p []byte) {
	select {
	case c.send <- p:
	case <-c.closed:
	default:
		c.close() // cannot keep up
	}
}

// connect: CONNECT -> keep-alive seconds and return code (0 ok, 1 protocol, 4 bad login, 5 not allowed)
func (b *Broker) connect(c *mqttSession, body []byte) (int, byte) {
	proto, rest, err := mqttString(body)
	if err != nil || len(rest) < 4 || (proto != "MQTT" && proto != "MQIsdp") {
		return 0, 1
	}
	flags := rest[1]
	keep := int(binary.BigEndian.Uint16(rest[2:4]))
	rest = rest[4:]
	if c.clientID, rest, err = mqttString(rest); err != nil {
		return 0, 2
	}
	if flags&0x04 != 0 { // will
		if _, rest, err = mqttString(rest); err != nil {
			return 0, 1
		}
		if _, rest, err = mqttString(rest); err != nil {
			return 0, 1
		}
	}
	pw := ""
	if flags&0x80 != 0 {
		if c.username, rest, err = mqttString(rest); err != nil {
			return 0, 1
		}
	}
	if flags&0x40 != 0 {
		if pw, _, err = mqttString(rest); err != nil {
			return 0, 1
		}
	}
	if c.username == "" {
		return keep, 5
	}
	if !b.srv.checkLogin(c.username, pw, false) {
		return keep, 4
	}
	return keep, 0
}

func (b *Broker) publish(c *mqttSession, flags byte, body []byte) {
	qos := (flags >> 1) & 3
	topic, rest, err := mqttString(body)
	if err != nil || strings.ContainsAny(topic, "+#") {
		c.close()
		return
	}
	if qos > 0 {
		if len(rest) < 2 {
			c.close()
			return
		}
		id := rest[:2]
		rest = rest[2:]
		c.queue(mqttPacket(mqttPuback, 0, append([]byte(nil), id...)))
	}
	payload := append([]byte(nil), rest...)
	b.Deliver(topic, payload, c)
	if b.onPublish != nil {
		b.onPublish(topic, payload, c.username) // in order (name before position)
	}
}

// Deliver a message to every subscriber (QoS 0); from = sender session (nil = the server itself)
func (b *Broker) Deliver(topic string, payload []byte, from *mqttSession) {
	pkt := mqttPacket(mqttPublish, 0, append(appendString(nil, topic), payload...))
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.sessions {
		s.mu.Lock()
		match := false
		for _, f := range s.subs {
			if topicMatch(f, topic) {
				match = true
				break
			}
		}
		s.mu.Unlock()
		if match && s != from {
			s.queue(pkt)
		}
	}
}

func (b *Broker) subscribe(c *mqttSession, body []byte) {
	if len(body) < 2 {
		c.close()
		return
	}
	id, rest := body[:2], body[2:]
	var codes []byte
	for len(rest) > 0 {
		f, r, err := mqttString(rest)
		if err != nil || len(r) < 1 {
			c.close()
			return
		}
		rest = r[1:]
		c.mu.Lock()
		if !contains(c.subs, f) {
			c.subs = append(c.subs, f)
		}
		c.mu.Unlock()
		codes = append(codes, 0)
	}
	c.queue(mqttPacket(mqttSuback, 0, append(append([]byte(nil), id...), codes...)))
}

func (b *Broker) unsubscribe(c *mqttSession, body []byte) {
	if len(body) < 2 {
		c.close()
		return
	}
	id, rest := body[:2], body[2:]
	for len(rest) > 0 {
		f, r, err := mqttString(rest)
		if err != nil {
			c.close()
			return
		}
		rest = r
		c.mu.Lock()
		keep := c.subs[:0]
		for _, s := range c.subs {
			if s != f {
				keep = append(keep, s)
			}
		}
		c.subs = keep
		c.mu.Unlock()
	}
	c.queue(mqttPacket(mqttUnsuback, 0, append([]byte(nil), id...)))
}

// Clients: connected MQTT clients (radios) for the web UI
func (b *Broker) Clients() []map[string]any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []map[string]any
	for s := range b.sessions {
		out = append(out, map[string]any{"clientId": s.clientID, "username": s.username, "remote": s.remote})
	}
	return out
}
