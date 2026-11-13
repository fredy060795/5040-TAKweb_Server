package main

// Persistent state: one JSON file (state.json) in the data directory, written atomically.
// Small installations (a few hundred users and devices) need nothing more – no database server.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Config struct {
	ServerName    string `json:"serverName"`
	ServerUID     string `json:"serverUid"`
	PublicHost    string `json:"publicHost"`    // address the devices use (IP or DNS name); empty = automatic
	SetupDone     bool   `json:"setupDone"`     // first-run wizard finished
	EnableTCP     bool   `json:"enableTcp"`     // unencrypted CoT on port 8088 (no login)
	AnonHTTP      bool   `json:"anonHttp"`      // data packages over plain HTTP 8080 without login
	CertPassword  string `json:"certPassword"`  // password of the .p12 files handed to the devices
	WebCert       string `json:"webCert"`       // optional own certificate for the web/API ports (e.g. Let's Encrypt)
	WebKey        string `json:"webKey"`        //
	FedEnabled    bool   `json:"fedEnabled"`    // accept federation connections
	SendLatestSA  bool   `json:"sendLatestSa"`  // newly connected devices get the positions of everyone online
	ContactMaxAge int    `json:"contactMaxAge"` // minutes a contact stays in the latest-SA cache after its last report

	VideoEnabled  bool    `json:"videoEnabled"`  // run the video server (MediaMTX)
	VideoReadAuth bool    `json:"videoReadAuth"` // watching video needs a login (publishing always does)
	MediaMTXPath  string  `json:"mediamtxPath"`  // own MediaMTX program; empty = bundled / downloaded automatically
	VideoFedShare bool    `json:"videoFedShare"` // offer video feeds to federated servers
	Lat           float64 `json:"lat"`           // position of this server (marker of the TAK server bridge)
	Lon           float64 `json:"lon"`           //

	MQTTOff   bool `json:"mqttOff"`   // no MQTT broker for Meshtastic radios (port 8883)
	MQTTPlain bool `json:"mqttPlain"` // also MQTT without TLS on port 1883
}

type Membership struct {
	Group     string `json:"group"`
	Direction string `json:"direction"` // IN = may send to the group, OUT = receives from the group
}

type User struct {
	ID        int          `json:"id"`
	Username  string       `json:"username"`
	PassHash  string       `json:"passHash"`
	Admin     bool         `json:"admin"`
	Active    bool         `json:"active"`
	Created   time.Time    `json:"created"`
	LastLogin time.Time    `json:"lastLogin,omitempty"`
	PrevLogin time.Time    `json:"prevLogin,omitempty"`
	Groups    []Membership `json:"groups"`
	APIToken  string       `json:"apiToken,omitempty"` // token for the OTS-compatible API
}

type Group struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Created     time.Time `json:"created"`
}

// One-time / limited enrollment token (ATAK QR code "token=")
type EnrollToken struct {
	Token    string    `json:"token"`
	Username string    `json:"username"`
	MaxUses  int       `json:"maxUses"` // 0 = unlimited
	Uses     int       `json:"uses"`
	Expires  time.Time `json:"expires,omitempty"`
	Created  time.Time `json:"created"`
}

type IssuedCert struct {
	Serial    string    `json:"serial"`
	Username  string    `json:"username"`
	ClientUID string    `json:"clientUid,omitempty"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
	Revoked   bool      `json:"revoked"`
}

type EUD struct {
	UID           string    `json:"uid"`
	Callsign      string    `json:"callsign"`
	Username      string    `json:"username"`
	Device        string    `json:"device"`
	Platform      string    `json:"platform"`
	OS            string    `json:"os"`
	Version       string    `json:"version"`
	Team          string    `json:"team"`
	Role          string    `json:"role"`
	Phone         string    `json:"phone"`
	LastEventTime time.Time `json:"lastEventTime"`
	LastStatus    string    `json:"lastStatus"`
	Lat           float64   `json:"lat"`
	Lon           float64   `json:"lon"`
}

type Package struct {
	Hash       string    `json:"hash"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	MIME       string    `json:"mime"`
	Keywords   []string  `json:"keywords"`
	CreatorUID string    `json:"creatorUid"`
	User       string    `json:"user"`
	Tool       string    `json:"tool"` // "public" = visible in the data package list of the devices
	Submitted  time.Time `json:"submitted"`
	Origin     string    `json:"origin"` // "local" or "federation:<server name>"
	PrimaryKey int       `json:"primaryKey"`
}

type Mission struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatorUID  string    `json:"creatorUid"`
	Tool        string    `json:"tool"`
	Password    string    `json:"password,omitempty"`
	Groups      []string  `json:"groups"`
	DefaultRole string    `json:"defaultRole"`
	Created     time.Time `json:"created"`
	UIDs        []string  `json:"uids"`     // old format, read once and moved to Items
	Contents    []string  `json:"contents"` // old format, read once and moved to Files

	// Data Sync (like TAK Server): map items, files, subscribers, change log
	GUID     string            `json:"guid"`
	PassHash string            `json:"passHash,omitempty"`
	Keywords []string          `json:"keywords"`
	ChatRoom string            `json:"chatRoom"`
	Items    []*MissionItem    `json:"items"`
	Files    []*MissionFile    `json:"files"`
	CoT      map[string]string `json:"cot"` // uid -> latest event
	Subs     []*MissionSub     `json:"subs"`
	Changes  []*MissionChange  `json:"changes"`
}

type MissionItem struct {
	UID        string    `json:"uid"`
	CreatorUID string    `json:"creatorUid"`
	Time       time.Time `json:"time"`
	Type       string    `json:"type"`
	Callsign   string    `json:"callsign"`
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
}

type MissionFile struct {
	Hash       string    `json:"hash"`
	CreatorUID string    `json:"creatorUid"`
	Time       time.Time `json:"time"`
}

type MissionSub struct {
	ClientUID string    `json:"clientUid"`
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	Time      time.Time `json:"time"`
}

type MissionChange struct {
	Type       string    `json:"type"` // CREATE_MISSION, ADD_CONTENT, REMOVE_CONTENT
	Time       time.Time `json:"time"`
	CreatorUID string    `json:"creatorUid"`
	UID        string    `json:"uid,omitempty"`  // map item
	Hash       string    `json:"hash,omitempty"` // file
}

type MeshChannel struct {
	ID      int       `json:"id"`
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	PSK     string    `json:"psk"`
	Data    string    `json:"data"` // everything else the tool sent (JSON)
	Created time.Time `json:"created"`
}

type Profile struct {
	ID         int    `json:"id"`
	EUDUID     string `json:"eudUid"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	ValueClass string `json:"valueClass"`
	Enrollment bool   `json:"enrollment"`
	Connection bool   `json:"connection"`
	Active     bool   `json:"active"`
}

// VideoFeed: either a stream on the video server (Path set; Source = address it is pulled from, empty
// = a camera/drone pushes it) or only a link to video somewhere else (URL set).
type VideoFeed struct {
	UID     string    `json:"uid"`
	Alias   string    `json:"alias"`
	URL     string    `json:"url,omitempty"`
	Path    string    `json:"path,omitempty"`
	Source  string    `json:"source,omitempty"`
	User    string    `json:"user,omitempty"`
	Created time.Time `json:"created"`
}

// Bridge: connection to another TAK server (OpenTAKServer, TAK Server, FreeTAKServer) as a client.
// That server sees the bridge as one device; data flows in both directions.
type Bridge struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	StreamPort  int       `json:"streamPort"` // 8089 (SSL) or 8088 (TCP)
	EnrollPort  int       `json:"enrollPort"` // 8446
	APIPort     int       `json:"apiPort"`    // 8443 (Marti with client certificate)
	WebPort     int       `json:"webPort"`    // 443 (OTS web API, for sharing video)
	RTSPPort    int       `json:"rtspPort"`   // 8554 (MediaMTX of the other server)
	TLS         bool      `json:"tls"`
	Username    string    `json:"username"`
	Password    string    `json:"password"` // needed to renew the certificate and to watch its video
	CertPEM     string    `json:"certPem,omitempty"`
	KeyPEM      string    `json:"keyPem,omitempty"`
	CAPEM       string    `json:"caPem,omitempty"`
	UID         string    `json:"uid"`
	Callsign    string    `json:"callsign"`
	Enabled     bool      `json:"enabled"`
	Groups      []string  `json:"groups"`      // local groups shared; empty = all
	ImportVideo bool      `json:"importVideo"` // show the other server's video feeds here
	ExportVideo bool      `json:"exportVideo"` // register our video feeds on the other server (OTS)
	Created     time.Time `json:"created"`
}

// Federation link to another server. Both sides keep a link record; the connection is made by the
// side that redeemed the invite ("outgoing") and carries data in both directions.
type FedLink struct {
	ID        string    `json:"id"`
	PeerUID   string    `json:"peerUid"`
	PeerName  string    `json:"peerName"`
	Outgoing  bool      `json:"outgoing"`
	Addresses []string  `json:"addresses"` // outgoing only: host:port candidates, tried in order
	Secret    string    `json:"secret"`
	Invite    string    `json:"invite,omitempty"` // outgoing, before the first connection: invite token
	PeerCAFP  string    `json:"peerCaFp"`         // SHA-256 of the peer's CA certificate (pinned)
	Enabled   bool      `json:"enabled"`
	Groups    []string  `json:"groups"`  // local groups shared with the peer; empty = everything
	Transit   bool      `json:"transit"` // forward data of other federated servers (A–B–C chains)
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"lastSeen,omitempty"`
}

type FedInvite struct {
	Token   string    `json:"token"`
	Label   string    `json:"label"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

type State struct {
	Config     Config              `json:"config"`
	Users      []*User             `json:"users"`
	Groups     []*Group            `json:"groups"`
	Tokens     []*EnrollToken      `json:"enrollTokens"`
	Certs      []*IssuedCert       `json:"certs"`
	EUDs       map[string]*EUD     `json:"euds"`
	Packages   map[string]*Package `json:"packages"`
	Missions   []*Mission          `json:"missions"`
	Profiles   []*Profile          `json:"profiles"`
	Videos     []*VideoFeed        `json:"videos"`
	FedLinks   []*FedLink          `json:"fedLinks"`
	FedInvites []*FedInvite        `json:"fedInvites"`
	Bridges    []*Bridge           `json:"bridges"`
	Mesh       []*MeshChannel      `json:"meshChannels"`
	VideoMigr  bool                `json:"videoMigrated"`
	NextID     int                 `json:"nextId"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	s     *State
	dirty chan struct{}
	done  chan struct{}
	wg    sync.WaitGroup
}

func defaultConfig() Config {
	return Config{
		ServerName:    "WebTAK Server",
		ServerUID:     randomHex(8),
		EnableTCP:     true,
		AnonHTTP:      true,
		CertPassword:  "atakatak",
		FedEnabled:    true,
		SendLatestSA:  true,
		ContactMaxAge: 30,
		VideoEnabled:  true,
		VideoFedShare: true,
	}
}

func OpenStore(dir string) (*Store, error) {
	st := &Store{path: filepath.Join(dir, "state.json"), dirty: make(chan struct{}, 1), done: make(chan struct{})}
	s := &State{Config: defaultConfig()}
	b, err := os.ReadFile(st.path)
	if err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, errors.New("state.json is damaged: " + err.Error())
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.Config.ServerUID == "" {
		s.Config.ServerUID = randomHex(8)
	}
	if s.Config.CertPassword == "" {
		s.Config.CertPassword = "atakatak"
	}
	if s.EUDs == nil {
		s.EUDs = map[string]*EUD{}
	}
	if s.Packages == nil {
		s.Packages = map[string]*Package{}
	}
	if !s.VideoMigr { // state from before the video server existed
		s.Config.VideoEnabled, s.Config.VideoFedShare, s.VideoMigr = true, true, true
	}
	if s.NextID == 0 {
		s.NextID = 1
	}
	st.s = s
	// The default group every user and every unencrypted client belongs to (same name as in OTS / TAK Server)
	st.Update(func(s *State) {
		if findGroup(s, AnonGroup) == nil {
			s.Groups = append(s.Groups, &Group{ID: s.nextID(), Name: AnonGroup, Description: "Default group", Created: time.Now()})
		}
	})
	if err := st.flush(); err != nil {
		return nil, err
	}
	st.wg.Add(1)
	go st.writer()
	return st, nil
}

func (s *State) nextID() int { id := s.NextID; s.NextID++; return id }

// Read gives read access to the state; fn must not keep references after returning.
func (st *Store) Read(fn func(s *State)) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	fn(st.s)
}

// Update changes the state and schedules a save.
func (st *Store) Update(fn func(s *State)) {
	st.mu.Lock()
	fn(st.s)
	st.mu.Unlock()
	select {
	case st.dirty <- struct{}{}:
	default:
	}
}

func (st *Store) Config() Config {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.s.Config
}

func (st *Store) writer() {
	defer st.wg.Done()
	for {
		select {
		case <-st.dirty:
			time.Sleep(300 * time.Millisecond) // collect bursts of changes
			if err := st.flush(); err != nil {
				logf("ERROR saving state: %v", err)
			}
		case <-st.done:
			return
		}
	}
}

func (st *Store) flush() error {
	st.mu.RLock()
	b, err := json.MarshalIndent(st.s, "", " ")
	st.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

func (st *Store) Close() error {
	close(st.done)
	st.wg.Wait()
	return st.flush()
}

func findUser(s *State, name string) *User {
	for _, u := range s.Users {
		if u.Username == name {
			return u
		}
	}
	return nil
}

func findGroup(s *State, name string) *Group {
	for _, g := range s.Groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}
