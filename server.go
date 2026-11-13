package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Version is set at build time (-ldflags "-X main.Version=…")
var Version = "1.0.0"

type Ports struct {
	TCP       int // CoT unencrypted
	SSL       int // CoT TLS with client certificate
	HTTPS     int // Marti API + web UI
	HTTP      int // Marti API (plain) + web UI for this computer
	Enroll    int // certificate enrollment (ATAK / iTAK QR)
	Fed       int // federation
	MQTT      int // MQTT with TLS for Meshtastic radios
	MQTTPlain int // MQTT without TLS (only if switched on)

	// video server (MediaMTX), same ports as in OpenTAKServer
	RTSP      int
	RTMP      int
	HLS       int
	WebRTC    int
	WebRTCUDP int
	SRT       int
	RTP       int // RTP, RTCP = RTP+1
	MediaAPI  int // MediaMTX control API, only on 127.0.0.1
}

func DefaultPorts() Ports {
	return Ports{TCP: 8088, SSL: 8089, HTTPS: 8443, HTTP: 8080, Enroll: 8446, Fed: 9000, MQTT: 8883, MQTTPlain: 1883,
		RTSP: 8554, RTMP: 1935, HLS: 8888, WebRTC: 8889, WebRTCUDP: 8189, SRT: 8890, RTP: 8000, MediaAPI: 9997}
}

type Server struct {
	dataDir  string
	ports    Ports
	bindAddr string
	store    *Store
	pki      *PKI
	hub      *Hub
	fed      *Federation
	packages *PackageStore
	media    *Media
	bridges  *Bridges
	broker   *Broker
	mesh     *Meshtastic
	sessions *sessionStore
	started  time.Time

	listeners []net.Listener
	https     []*http.Server
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewServer(dataDir string, ports Ports) (*Server, error) {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs // child programs (MediaMTX) run in other folders
	}
	st, err := OpenStore(dataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{dataDir: dataDir, ports: ports, store: st, started: time.Now(), sessions: newSessionStore()}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.pki, err = LoadPKI(filepath.Join(dataDir, "certs"), st.Config().ServerName, func() []string {
		return []string{s.store.Config().PublicHost}
	})
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	if c := st.Config(); c.WebCert != "" {
		if err := s.pki.SetWebCert(c.WebCert, c.WebKey); err != nil {
			logf("Own web certificate not loaded: %v", err)
		}
	}
	s.packages, err = OpenPackageStore(filepath.Join(dataDir, "packages"), st)
	if err != nil {
		return nil, err
	}
	s.hub = NewHub(s)
	s.fed = NewFederation(s)
	s.hub.fed = s.fed
	s.media = NewMedia(s)
	s.bridges = NewBridges(s)
	s.broker = NewBroker(s)
	s.mesh = NewMeshtastic(s)
	s.broker.onPublish = func(topic string, payload []byte, user string) { s.mesh.Handle(topic, payload, user) }
	return s, nil
}

func (s *Server) listen(port int) (net.Listener, int, error) {
	l, err := net.Listen("tcp", joinHostPort(s.bindAddr, port))
	if err != nil {
		return nil, 0, err
	}
	s.listeners = append(s.listeners, l)
	return l, l.Addr().(*net.TCPAddr).Port, nil
}

// Start opens all ports. A port that is in use is reported but does not stop the others.
func (s *Server) Start() error {
	cfg := s.store.Config()
	var problems []string
	try := func(name string, port *int, fn func(net.Listener)) {
		if *port < 0 {
			return
		}
		l, p, err := s.listen(*port)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s port %d: %v", name, *port, err))
			return
		}
		*port = p
		fn(l)
	}
	if cfg.EnableTCP {
		try("CoT TCP", &s.ports.TCP, func(l net.Listener) { s.serveCoT(l, false) })
	} else {
		s.ports.TCP = -1
	}
	try("CoT SSL", &s.ports.SSL, func(l net.Listener) { s.serveCoT(l, true) })
	try("HTTPS", &s.ports.HTTPS, func(l net.Listener) { s.serveHTTP(l, "https") })
	try("HTTP", &s.ports.HTTP, func(l net.Listener) { s.serveHTTP(l, "http") })
	try("Enrollment", &s.ports.Enroll, func(l net.Listener) { s.serveHTTP(l, "enroll") })
	try("Federation", &s.ports.Fed, func(l net.Listener) { s.fed.Serve(l) })
	if !cfg.MQTTOff {
		try("MQTT (TLS)", &s.ports.MQTT, func(l net.Listener) { s.serveMQTT(l, true) })
	} else {
		s.ports.MQTT = -1
	}
	if cfg.MQTTPlain {
		try("MQTT", &s.ports.MQTTPlain, func(l net.Listener) { s.serveMQTT(l, false) })
	} else {
		s.ports.MQTTPlain = -1
	}
	for _, p := range problems {
		logf("WARNING %s", p)
	}
	if s.ports.SSL <= 0 && s.ports.HTTPS <= 0 && s.ports.HTTP <= 0 {
		return errors.New("no port could be opened: " + strings.Join(problems, "; "))
	}
	if err := s.media.Start(); err != nil {
		logf("WARNING video server: %v", err)
	}
	s.fed.Start()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.mesh.down.run(s.ctx.Done()) }()
	s.bridges.Start()
	s.wg.Add(1)
	go s.maintenance()
	return nil
}

func (s *Server) Close() {
	s.cancel()
	for _, l := range s.listeners {
		l.Close()
	}
	for _, h := range s.https {
		h.Close()
	}
	for _, c := range s.hub.Clients() {
		c.Close()
	}
	s.fed.Stop()
	s.bridges.Stop()
	s.media.Stop()
	s.wg.Wait()
	s.store.Close()
}

// maintenance: renew the server certificate when the IP changes, reload own web certificate
func (s *Server) maintenance() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if err := s.pki.ensureServerCert(); err != nil {
				logf("Server certificate: %v", err)
			}
			if c := s.store.Config(); c.WebCert != "" {
				if err := s.pki.SetWebCert(c.WebCert, c.WebKey); err != nil {
					logf("Own web certificate: %v", err)
				}
			}
		}
	}
}

// PublicHost: address for QR codes, data packages and invites.
func (s *Server) PublicHost() string {
	if h := strings.TrimSpace(s.store.Config().PublicHost); h != "" {
		return h
	}
	if ips := localIPs(); len(ips) > 0 {
		return ips[0]
	}
	return "127.0.0.1"
}

// userGroups returns the IN and OUT groups of an active user.
func (s *Server) userGroups(username string) (in, out []string, ok bool) {
	s.store.Read(func(st *State) {
		u := findUser(st, username)
		if u == nil || !u.Active {
			return
		}
		ok = true
		for _, m := range u.Groups {
			if m.Direction == "IN" {
				in = append(in, m.Group)
			} else {
				out = append(out, m.Group)
			}
		}
	})
	return
}

// ---------- CoT streaming ports ----------

func (s *Server) tlsConfigCoT() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      s.pki.CAPool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.pki.ServerCert(), nil },
	}
}

// certUser checks a verified client certificate: not revoked, user exists and is active.
func (s *Server) certUser(cert *x509.Certificate) (string, error) {
	serial := serialHex(cert)
	name := cert.Subject.CommonName
	var err error
	s.store.Read(func(st *State) {
		for _, c := range st.Certs {
			if c.Serial == serial && c.Revoked {
				err = errors.New("certificate revoked")
				return
			}
		}
		u := findUser(st, name)
		if u == nil {
			err = fmt.Errorf("user %q does not exist", name)
		} else if !u.Active {
			err = fmt.Errorf("user %q is blocked", name)
		}
	})
	return name, err
}

func (s *Server) serveCoT(l net.Listener, useTLS bool) {
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
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(30 * time.Second)
			}
			go s.handleCoTConn(conn, useTLS)
		}
	}()
}

func (s *Server) handleCoTConn(conn net.Conn, useTLS bool) {
	remote := conn.RemoteAddr().String()
	username := ""
	if useTLS {
		tc := tls.Server(conn, s.tlsConfigCoT())
		tc.SetDeadline(time.Now().Add(20 * time.Second))
		if err := tc.Handshake(); err != nil {
			logf("TLS connection from %s rejected: %v", remote, err)
			conn.Close()
			return
		}
		tc.SetDeadline(time.Time{})
		certs := tc.ConnectionState().PeerCertificates
		var err error
		if username, err = s.certUser(certs[0]); err != nil {
			logf("TLS connection from %s rejected: %v", remote, err)
			tc.Close()
			return
		}
		conn = tc
	}
	c := &Client{
		ID: s.hub.nextID.Add(1), conn: conn, Remote: remote, TLS: useTLS, Username: username,
		LocalHost: hostOnly(conn.LocalAddr().String()), Connected: time.Now(),
		send: make(chan []byte, 2048), closed: make(chan struct{}),
	}
	if username != "" {
		in, out, _ := s.userGroups(username)
		c.inG, c.outG = in, out
	} else {
		c.inG, c.outG = []string{AnonGroup}, []string{AnonGroup}
	}
	s.hub.Add(c)
	logf("Connected: %s (%s)%s", remote, map[bool]string{true: "SSL", false: "TCP"}[useTLS], map[bool]string{true: " user=" + username, false: ""}[username != ""])
	go func() { // writer
		for {
			select {
			case b := <-c.send:
				conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := conn.Write(b); err != nil {
					c.Close()
					return
				}
			case <-c.closed:
				return
			}
		}
	}()
	er := NewEventReader(conn)
	for {
		raw, err := er.Next()
		if err != nil {
			if err != io.EOF && s.ctx.Err() == nil && !isClosedErr(err) {
				logf("Connection %s ended: %v", remote, err)
			}
			break
		}
		s.hub.FromClient(c, raw)
	}
	c.Close()
	s.hub.Remove(c)
	logf("Disconnected: %s %s", remote, c.Callsign)
}

func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed") || strings.Contains(err.Error(), "connection reset")
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
