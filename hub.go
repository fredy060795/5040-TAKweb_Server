package main

// Message routing between connected devices and federated servers.
//
// Groups work like in OpenTAKServer / TAK Server: a device sends into its IN groups and receives
// from its OUT groups. Unencrypted (port 8088) clients are in __ANON__ (IN and OUT).

import (
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	ID        int64
	conn      net.Conn
	Remote    string
	LocalHost string // address of this server as the device sees it (for download links)
	TLS       bool
	Username  string
	Connected time.Time

	mu       sync.RWMutex
	UID      string
	Callsign string
	inG      []string
	outG     []string
	lastSeen time.Time
	sent     atomic.Int64
	recv     atomic.Int64

	send   chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *Client) Close() {
	c.once.Do(func() {
		close(c.closed)
		c.conn.Close()
	})
}

// Send queues data; a device that cannot keep up is disconnected instead of slowing everyone down.
func (c *Client) Send(b []byte) {
	select {
	case c.send <- b:
	case <-c.closed:
	default:
		logf("Client %s (%s) too slow – disconnecting", c.Callsign, c.Remote)
		c.Close()
	}
}

func (c *Client) groups() (in, out []string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.inG, c.outG
}

type cachedSA struct {
	raw     []byte
	ev      *Event
	groups  []string // IN groups of the sender; nil = federated, visible to all
	viaLink string   // federation link id it came from ("" = local)
	at      time.Time
}

type Hub struct {
	srv     *Server
	mu      sync.RWMutex
	clients map[int64]*Client
	latest  map[string]*cachedSA
	nextID  atomic.Int64
	fed     *Federation
	seen    *dedupe
}

func NewHub(srv *Server) *Hub {
	return &Hub{srv: srv, clients: map[int64]*Client{}, latest: map[string]*cachedSA{}, seen: newDedupe()}
}

func (h *Hub) Add(c *Client) {
	h.mu.Lock()
	h.clients[c.ID] = c
	h.mu.Unlock()
}

func (h *Hub) Remove(c *Client) {
	h.mu.Lock()
	delete(h.clients, c.ID)
	h.mu.Unlock()
	c.mu.RLock()
	uid := c.UID
	c.mu.RUnlock()
	if uid != "" && !h.uidOnline(uid) {
		h.srv.store.Update(func(s *State) {
			if e := s.EUDs[uid]; e != nil {
				e.LastStatus = "Disconnected"
			}
		})
	}
}

func (h *Hub) uidOnline(uid string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		c.mu.RLock()
		u := c.UID
		c.mu.RUnlock()
		if u == uid {
			return true
		}
	}
	return false
}

func (h *Hub) Clients() []*Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RefreshGroups updates the groups of connected clients after users/groups changed;
// clients of deleted or blocked users are disconnected.
func (h *Hub) RefreshGroups() {
	for _, c := range h.Clients() {
		if c.Username == "" {
			continue
		}
		in, out, ok := h.srv.userGroups(c.Username)
		if !ok {
			logf("User %s is no longer allowed – disconnecting %s", c.Username, c.Remote)
			c.Close()
			continue
		}
		c.mu.Lock()
		c.inG, c.outG = in, out
		c.mu.Unlock()
	}
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// FromClient handles an event sent by a local device.
func (h *Hub) FromClient(c *Client, raw []byte) {
	c.recv.Add(1)
	ev, err := ParseEvent(raw)
	if err != nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	c.lastSeen = now
	c.mu.Unlock()
	if ev.Type == "t-x-c-t" { // ping
		c.Send(PongEvent())
		return
	}
	if ev.IsSA() {
		h.trackSA(c, ev, raw)
	}
	if h.srv.missionCoT(raw, ev, c) {
		return // Data Sync: goes to the mission's subscribers
	}
	in, _ := c.groups()
	h.route(raw, ev, c, "", in)
}

func (h *Hub) trackSA(c *Client, ev *Event, raw []byte) {
	c.mu.Lock()
	first := c.UID == ""
	c.UID, c.Callsign = ev.UID, ev.Callsign()
	in := c.inG
	c.mu.Unlock()
	if first {
		logf("Device online: %s (%s) from %s user=%s", ev.Callsign(), ev.UID, c.Remote, c.Username)
		h.sendLatestTo(c)
	}
	h.mu.Lock()
	h.latest[ev.UID] = &cachedSA{raw: raw, ev: ev, groups: in, at: time.Now()}
	h.mu.Unlock()
	h.srv.store.Update(func(s *State) {
		e := s.EUDs[ev.UID]
		if e == nil {
			e = &EUD{UID: ev.UID}
			s.EUDs[ev.UID] = e
		}
		e.Callsign = ev.Callsign()
		if c.Username != "" {
			e.Username = c.Username
		}
		if t := ev.Detail.Takv; t != nil {
			e.Device, e.Platform, e.OS, e.Version = t.Device, t.Platform, t.OS, t.Version
		}
		if g := ev.Detail.Group; g != nil {
			e.Team, e.Role = g.Name, g.Role
		}
		if ev.Detail.Contact.Phone != "" {
			e.Phone = ev.Detail.Contact.Phone
		}
		e.Lat, e.Lon = ev.Point.Lat, ev.Point.Lon
		e.LastEventTime = time.Now()
		e.LastStatus = "Connected"
	})
}

// sendLatestTo gives a newly connected device the current position of everyone it may see.
func (h *Hub) sendLatestTo(c *Client) {
	if !h.srv.store.Config().SendLatestSA {
		return
	}
	_, out := c.groups()
	h.mu.RLock()
	defer h.mu.RUnlock()
	for uid, sa := range h.latest {
		if uid == c.UID || time.Now().After(sa.ev.StaleTime()) {
			continue
		}
		if sa.groups != nil && !intersects(sa.groups, out) {
			continue
		}
		c.Send(h.forClient(sa.raw, sa.ev, c))
	}
}

// fedSource: a federated WebTAK Server or a bridged TAK server.
type fedSource interface {
	sourceID() string
	localGroups() []string
}

func (c *fedConn) sourceID() string { return c.getLink().ID }

// FromFederation handles an event received from a federated server or a bridge.
func (h *Hub) FromFederation(l fedSource, raw []byte) {
	ev, err := ParseEvent(raw)
	if err != nil {
		return
	}
	tag := h.fedTag()
	if ev.HasFlowTag(tag) || h.seen.check(raw) {
		return // already passed this server (loop) or duplicate
	}
	if ev.IsSA() {
		h.mu.Lock()
		h.latest[ev.UID] = &cachedSA{raw: raw, ev: ev, viaLink: l.sourceID(), at: time.Now()}
		h.mu.Unlock()
	}
	h.route(raw, ev, nil, l.sourceID(), l.localGroups())
}

// FromMesh handles an event the server made from a Meshtastic radio's MQTT message (meshtastic.go): visible to
// everyone (like OpenTAKServer), kept as the latest position, passed on to federated servers.
func (h *Hub) FromMesh(raw []byte) {
	ev, err := ParseEvent(raw)
	if err != nil {
		return
	}
	if ev.IsSA() {
		h.mu.Lock()
		h.latest[ev.UID] = &cachedSA{raw: raw, ev: ev, at: time.Now()}
		h.mu.Unlock()
		h.srv.store.Update(func(s *State) {
			e := s.EUDs[ev.UID]
			if e == nil {
				e = &EUD{UID: ev.UID}
				s.EUDs[ev.UID] = e
			}
			e.Callsign = ev.Callsign()
			if t := ev.Detail.Takv; t != nil {
				e.Device, e.Platform = t.Device, t.Platform
			}
			e.Lat, e.Lon = ev.Point.Lat, ev.Point.Lon
			e.LastEventTime = time.Now()
			e.LastStatus = "Mesh (MQTT)"
		})
	}
	h.route(raw, ev, nil, "", nil)
}

func (h *Hub) fedTag() string { return "WebTAK-Server-" + h.srv.store.Config().ServerUID }

// route delivers an event to local devices and federated servers.
// srcClient = local sender (nil if federated), viaLink = federation link it came in on.
// groups = groups the event is visible in (nil/empty for federated = everyone).
func (h *Hub) route(raw []byte, ev *Event, srcClient *Client, viaLink string, groups []string) {
	callsigns, uids := ev.Destinations()
	directed := len(callsigns)+len(uids) > 0
	found := 0
	for _, c := range h.Clients() {
		if c == srcClient {
			continue
		}
		c.mu.RLock()
		cuid, ccs, out := c.UID, c.Callsign, c.outG
		c.mu.RUnlock()
		if directed {
			if !(contains(uids, cuid) && cuid != "") && !(contains(callsigns, ccs) && ccs != "") {
				continue
			}
			found++
		} else if len(groups) > 0 && !intersects(groups, out) {
			continue
		}
		c.Send(h.forClient(raw, ev, c))
		c.sent.Add(1)
	}
	if h.fed == nil {
		return
	}
	if directed && found >= len(callsigns)+len(uids) && viaLink == "" {
		return // every recipient is local
	}
	h.fed.Broadcast(raw, ev, viaLink, groups, srcClient != nil)
	if h.srv.bridges != nil {
		h.srv.bridges.Broadcast(raw, ev, viaLink, groups)
	}
}

// forClient adapts an event for one device: download links of shared data packages point to
// this server under the address the device uses.
func (h *Hub) forClient(raw []byte, ev *Event, c *Client) []byte {
	fs := ev.Detail.Fileshare
	if fs == nil || fs.SHA256 == "" || !h.srv.packages.Has(fs.SHA256) {
		return raw
	}
	port, scheme := h.srv.ports.HTTPS, "https"
	if !c.TLS {
		port, scheme = h.srv.ports.HTTP, "http"
	}
	return RewriteSenderURL(raw, scheme+"://"+joinHostPort(c.LocalHost, port)+"/Marti/sync/content?hash="+fs.SHA256)
}

// Broadcast an event created by the server itself (chat from the web UI).
func (h *Hub) ServerBroadcast(raw []byte) {
	ev, err := ParseEvent(raw)
	if err != nil {
		return
	}
	h.route(raw, ev, nil, "", nil)
}

// Contacts known to the server (latest positions), for the map and the client list.
func (h *Hub) Contacts() []map[string]any {
	h.mu.Lock()
	maxAge := time.Duration(h.srv.store.Config().ContactMaxAge) * time.Minute
	if maxAge <= 0 {
		maxAge = 30 * time.Minute
	}
	var out []map[string]any
	for uid, sa := range h.latest {
		if time.Since(sa.at) > maxAge && time.Now().After(sa.ev.StaleTime()) {
			delete(h.latest, uid)
			continue
		}
		team, role := "", ""
		if g := sa.ev.Detail.Group; g != nil {
			team, role = g.Name, g.Role
		}
		origin := "local"
		if sa.viaLink != "" {
			origin = "federation"
			if strings.HasPrefix(sa.viaLink, "bridge:") {
				origin = "TAK server: " + h.srv.bridges.name(strings.TrimPrefix(sa.viaLink, "bridge:"))
			} else if h.fed != nil {
				origin = "federation: " + h.fed.linkName(sa.viaLink)
			}
		}
		out = append(out, map[string]any{
			"uid": uid, "callsign": sa.ev.Callsign(), "type": sa.ev.Type, "lat": sa.ev.Point.Lat, "lon": sa.ev.Point.Lon,
			"team": team, "role": role, "time": sa.at, "stale": time.Now().After(sa.ev.StaleTime()), "origin": origin,
		})
	}
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]["callsign"].(string)) < strings.ToLower(out[j]["callsign"].(string))
	})
	return out
}

// LatestForFederation: positions to send to a peer when a link comes up.
func (h *Hub) LatestForFederation(linkID string) [][]byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out [][]byte
	for _, sa := range h.latest {
		if sa.viaLink == linkID || time.Now().After(sa.ev.StaleTime()) {
			continue
		}
		out = append(out, sa.raw)
	}
	return out
}

// ---------- duplicate filter for federation (same event over two paths) ----------

type dedupe struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

func newDedupe() *dedupe { return &dedupe{seen: map[[32]byte]time.Time{}} }

func (d *dedupe) check(raw []byte) bool {
	k := sha256Sum(stripFlowTags(raw))
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if t, ok := d.seen[k]; ok && now.Sub(t) < 30*time.Second {
		return true
	}
	d.seen[k] = now
	if len(d.seen) > 20000 {
		for key, t := range d.seen {
			if now.Sub(t) > 30*time.Second {
				delete(d.seen, key)
			}
		}
	}
	return false
}

func stripFlowTags(raw []byte) []byte { return reFlowTags.ReplaceAll(raw, nil) }
