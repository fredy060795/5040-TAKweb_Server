package main

// JSON API of the web interface (/admin/api/...).

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

// ---------- sessions ----------

type session struct {
	user    string
	expires time.Time
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]session
}

func newSessionStore() *sessionStore { return &sessionStore{m: map[string]session{}} }

func (ss *sessionStore) create(user string) string {
	tok := randomHex(24)
	ss.mu.Lock()
	ss.m[tok] = session{user: user, expires: time.Now().Add(7 * 24 * time.Hour)}
	ss.mu.Unlock()
	return tok
}

func (ss *sessionStore) get(tok string) string {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, ok := ss.m[tok]
	if !ok || time.Now().After(s.expires) {
		delete(ss.m, tok)
		return ""
	}
	return s.user
}

func (ss *sessionStore) drop(tok string) {
	ss.mu.Lock()
	delete(ss.m, tok)
	ss.mu.Unlock()
}

func (ss *sessionStore) dropUser(user string) {
	ss.mu.Lock()
	for k, s := range ss.m {
		if s.user == user {
			delete(ss.m, k)
		}
	}
	ss.mu.Unlock()
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, user string) {
	http.SetCookie(w, &http.Cookie{Name: "wts_session", Value: s.sessions.create(user), Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 7 * 24 * 3600})
}

// ---------- router ----------

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	route := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/api/"), "/")
	seg := strings.Split(route, "/")
	m := r.Method
	// requests that change something must come from our own page (CSRF protection)
	if m != http.MethodGet && r.Header.Get("X-WTS") != "1" {
		jsonErr(w, 403, "missing request header")
		return
	}
	cfg := s.store.Config()

	switch {
	case route == "state" && m == "GET":
		out := map[string]any{"setupDone": cfg.SetupDone, "serverName": cfg.ServerName, "version": Version}
		if !cfg.SetupDone {
			out["ips"], out["hostname"] = localIPs(), hostname()
		}
		if id := s.webUser(r); id != nil {
			out["user"], out["admin"] = id.User, id.Admin
		}
		writeJSON(w, 200, out)
		return
	case route == "setup" && m == "POST":
		s.apiSetup(w, r)
		return
	case route == "login" && m == "POST":
		var b struct{ Username, Password string }
		readJSON(r, &b)
		b.Username = strings.TrimSpace(b.Username)
		if !s.checkLogin(b.Username, b.Password, false) {
			time.Sleep(700 * time.Millisecond)
			jsonErr(w, 401, "Wrong user name or password.")
			return
		}
		s.store.Update(func(st *State) {
			if u := findUser(st, b.Username); u != nil {
				u.PrevLogin, u.LastLogin = u.LastLogin, time.Now()
			}
		})
		s.setSessionCookie(w, r, b.Username)
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	case route == "logout" && m == "POST":
		if c, err := r.Cookie("wts_session"); err == nil {
			s.sessions.drop(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "wts_session", Value: "", Path: "/", MaxAge: -1})
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}

	id := s.webUser(r)
	if id == nil {
		jsonErr(w, 401, "Please log in.")
		return
	}
	// ----- for every user: own device setup -----
	switch {
	case route == "me/connect" && m == "POST":
		s.apiEnroll(w, r, id.User)
		return
	case route == "me/package" && m == "GET":
		s.apiPackage(w, r, id.User)
		return
	case route == "me/password" && m == "POST":
		var b struct{ Old, New string }
		readJSON(r, &b)
		if !s.checkLogin(id.User, b.Old, false) {
			jsonErr(w, 400, "The current password is wrong.")
			return
		}
		if len(b.New) < 8 {
			jsonErr(w, 400, "The new password needs at least 8 characters.")
			return
		}
		h := hashPassword(b.New)
		s.store.Update(func(st *State) {
			if u := findUser(st, id.User); u != nil {
				u.PassHash = h
			}
		})
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	case route == "qr" && m == "GET":
		png, err := qrPNG(r.URL.Query().Get("text"))
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
		return
	case route == "truststore" && m == "GET":
		b, _ := s.pki.TrustStoreP12(cfg.CertPassword)
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", `attachment; filename="truststore.p12"`)
		w.Write(b)
		return
	case route == "ca.pem" && m == "GET":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="webtak-server-ca.pem"`)
		w.Write(s.pki.CAPEM())
		return
	}
	if !id.Admin {
		jsonErr(w, 403, "Only administrators can do this.")
		return
	}

	switch {
	case route == "dashboard" && m == "GET":
		s.apiDashboard(w)
	case route == "users" && m == "GET":
		s.apiUsers(w)
	case route == "users" && m == "POST":
		s.apiCreateUser(w, r)
	case seg[0] == "users" && len(seg) == 2 && m == "PUT":
		s.apiUpdateUser(w, r, seg[1])
	case seg[0] == "users" && len(seg) == 2 && m == "DELETE":
		if seg[1] == id.User {
			jsonErr(w, 400, "You cannot delete yourself.")
			return
		}
		if err := s.DeleteUser(seg[1]); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case seg[0] == "users" && len(seg) == 3 && seg[2] == "package" && m == "GET":
		s.apiPackage(w, r, seg[1])
	case seg[0] == "users" && len(seg) == 3 && seg[2] == "enroll" && m == "POST":
		s.apiEnroll(w, r, seg[1])
	case route == "groups" && m == "GET":
		var out []map[string]any
		s.store.Read(func(st *State) {
			for _, g := range st.Groups {
				n := 0
				for _, u := range st.Users {
					for _, mb := range u.Groups {
						if mb.Group == g.Name && mb.Direction == "OUT" {
							n++
						}
					}
				}
				out = append(out, map[string]any{"name": g.Name, "description": g.Description, "members": n})
			}
		})
		writeJSON(w, 200, out)
	case route == "groups" && m == "POST":
		var b struct{ Name, Description string }
		readJSON(r, &b)
		if err := s.CreateGroup(b.Name, b.Description); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case seg[0] == "groups" && len(seg) == 2 && m == "DELETE":
		if err := s.DeleteGroup(seg[1]); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "clients" && m == "GET":
		s.apiClients(w)
	case seg[0] == "clients" && len(seg) == 2 && m == "DELETE":
		cid, _ := strconv.ParseInt(seg[1], 10, 64)
		for _, c := range s.hub.Clients() {
			if c.ID == cid {
				c.Close()
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "contacts" && m == "GET":
		writeJSON(w, 200, s.hub.Contacts())
	case route == "euds" && m == "GET":
		var out []EUD
		s.store.Read(func(st *State) {
			for _, e := range st.EUDs {
				out = append(out, *e)
			}
		})
		sort.Slice(out, func(i, j int) bool { return out[i].LastEventTime.After(out[j].LastEventTime) })
		writeJSON(w, 200, out)
	case seg[0] == "euds" && len(seg) == 2 && m == "DELETE":
		s.store.Update(func(st *State) { delete(st.EUDs, seg[1]) })
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "chat" && m == "POST":
		var b struct{ Text string }
		readJSON(r, &b)
		if strings.TrimSpace(b.Text) == "" {
			jsonErr(w, 400, "Empty message.")
			return
		}
		s.hub.ServerBroadcast(ServerChat(cfg.ServerUID, cfg.ServerName, b.Text))
		writeJSON(w, 200, map[string]any{"ok": true})
	case seg[0] == "federation":
		s.apiFederation(w, r, seg[1:])
	case route == "packages" && m == "GET":
		writeJSON(w, 200, s.packages.List())
	case route == "packages" && m == "POST":
		file, hdr, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, 400, "No file.")
			return
		}
		defer file.Close()
		pk, err := s.packages.Save(file, Package{Name: hdr.Filename, User: id.User, CreatorUID: "WebTAK-Server-" + cfg.ServerUID}, "")
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, pk)
	case seg[0] == "packages" && len(seg) == 2 && m == "GET":
		s.martiDownload(w, r, seg[1])
	case seg[0] == "packages" && len(seg) == 2 && m == "PUT":
		var b struct{ Tool string }
		readJSON(r, &b)
		s.store.Update(func(st *State) {
			if pk := st.Packages[seg[1]]; pk != nil && (b.Tool == "public" || b.Tool == "private") {
				pk.Tool = b.Tool
			}
		})
		writeJSON(w, 200, map[string]any{"ok": true})
	case seg[0] == "packages" && len(seg) == 2 && m == "DELETE":
		s.packages.Delete(seg[1])
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "video" && m == "GET":
		s.apiVideo(w, r, id.User)
	case route == "video/streams" && m == "POST":
		var b struct{ Path, Source, Alias string }
		readJSON(r, &b)
		if err := s.SaveStream(b.Path, b.Source, strings.TrimSpace(b.Alias), id.User, false); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case len(seg) > 2 && seg[0] == "video" && seg[1] == "streams" && m == "DELETE":
		if !s.DeleteStream(strings.Join(seg[2:], "/")) {
			jsonErr(w, 404, "Stream not found.")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "video/links" && m == "POST":
		var b struct{ Alias, URL string }
		readJSON(r, &b)
		if !strings.Contains(b.URL, "://") {
			jsonErr(w, 400, "Please enter a stream address like rtsp://… or https://….")
			return
		}
		s.store.Update(func(st *State) {
			st.Videos = append(st.Videos, &VideoFeed{UID: newUUID(), Alias: orDefault(strings.TrimSpace(b.Alias), b.URL), URL: strings.TrimSpace(b.URL), User: id.User, Created: time.Now()})
		})
		writeJSON(w, 200, map[string]any{"ok": true})
	case len(seg) == 3 && seg[0] == "video" && seg[1] == "links" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.Videos[:0]
			for _, v := range st.Videos {
				if v.UID != seg[2] {
					keep = append(keep, v)
				}
			}
			st.Videos = keep
		})
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "bridges" && m == "GET":
		writeJSON(w, 200, s.bridges.Status())
	case route == "bridges" && m == "POST":
		var b BridgeInput
		readJSON(r, &b)
		br, err := s.bridges.Add(b)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "name": br.Name})
	case len(seg) == 2 && seg[0] == "bridges" && m == "PUT":
		var b struct {
			Enabled, ImportVideo, ExportVideo *bool
			Groups                            *[]string
			Callsign                          *string
		}
		readJSON(r, &b)
		s.store.Update(func(st *State) {
			for _, x := range st.Bridges {
				if x.ID != seg[1] {
					continue
				}
				if b.Enabled != nil {
					x.Enabled = *b.Enabled
				}
				if b.ImportVideo != nil {
					x.ImportVideo = *b.ImportVideo
				}
				if b.ExportVideo != nil {
					x.ExportVideo = *b.ExportVideo
				}
				if b.Groups != nil {
					x.Groups = *b.Groups
				}
				if b.Callsign != nil && strings.TrimSpace(*b.Callsign) != "" {
					x.Callsign = strings.TrimSpace(*b.Callsign)
				}
			}
		})
		s.bridges.Reconcile()
		writeJSON(w, 200, map[string]any{"ok": true})
	case len(seg) == 2 && seg[0] == "bridges" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.Bridges[:0]
			for _, x := range st.Bridges {
				if x.ID != seg[1] {
					keep = append(keep, x)
				}
			}
			st.Bridges = keep
		})
		s.bridges.Reconcile()
		writeJSON(w, 200, map[string]any{"ok": true})
	case route == "meshtastic" && m == "GET":
		writeJSON(w, 200, s.mesh.Status())
	case route == "settings" && m == "GET":
		writeJSON(w, 200, s.settingsView())
	case route == "settings" && m == "PUT":
		s.apiSettings(w, r)
	case route == "logs" && m == "GET":
		writeJSON(w, 200, recentLogs())
	default:
		jsonErr(w, 404, "Unknown request.")
	}
}

func (s *Server) webUser(r *http.Request) *identity {
	c, err := r.Cookie("wts_session")
	if err != nil {
		return nil
	}
	name := s.sessions.get(c.Value)
	if name == "" {
		return nil
	}
	return s.ident(name, "session")
}

func qrPNG(text string) ([]byte, error) {
	if text == "" || len(text) > 2000 {
		return nil, fmt.Errorf("no text")
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	code.Scale = 6
	return code.PNG(), nil
}

func qrDataURL(text string) string {
	png, err := qrPNG(text)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// ---------- setup, dashboard ----------

func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	if s.store.Config().SetupDone {
		jsonErr(w, 400, "The server is already set up.")
		return
	}
	var b struct{ Username, Password, ServerName, PublicHost string }
	readJSON(r, &b)
	b.Username = strings.TrimSpace(b.Username)
	if b.Username == "" {
		b.Username = "admin"
	}
	if !validUsername(b.Username) {
		jsonErr(w, 400, "User name: letters, digits and _ - . @ only.")
		return
	}
	if len(b.Password) < 8 {
		jsonErr(w, 400, "The password needs at least 8 characters.")
		return
	}
	if err := s.CreateUser(b.Username, b.Password, true, nil); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	s.store.Update(func(st *State) {
		if n := strings.TrimSpace(b.ServerName); n != "" {
			st.Config.ServerName = n
		}
		st.Config.PublicHost = strings.TrimSpace(b.PublicHost)
		st.Config.SetupDone = true
	})
	s.pki.ensureServerCert()
	logf("Setup finished – administrator %q created", b.Username)
	s.setSessionCookie(w, r, b.Username)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiDashboard(w http.ResponseWriter) {
	cfg := s.store.Config()
	var users, euds, pkgs, links int
	s.store.Read(func(st *State) {
		users, euds, pkgs, links = len(st.Users), len(st.EUDs), len(st.Packages), len(st.FedLinks)
	})
	fedUp := 0
	for _, l := range s.fed.Status() {
		if l["connected"] == true {
			fedUp++
		}
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeJSON(w, 200, map[string]any{
		"serverName": cfg.ServerName, "serverUid": cfg.ServerUID, "version": Version, "started": s.started,
		"publicHost": s.PublicHost(), "configuredHost": cfg.PublicHost, "ips": localIPs(), "hostname": hostname(),
		"ports": s.ports, "os": runtime.GOOS + "/" + runtime.GOARCH, "memoryMB": mem.Sys / (1 << 20),
		"clients": len(s.hub.Clients()), "contacts": len(s.hub.Contacts()), "users": users, "euds": euds, "packages": pkgs,
		"fedLinks": links, "fedConnected": fedUp, "caFingerprint": s.pki.CAFingerprint(), "tcpEnabled": cfg.EnableTCP,
	})
}

func (s *Server) apiClients(w http.ResponseWriter) {
	out := []map[string]any{}
	for _, c := range s.hub.Clients() {
		c.mu.RLock()
		out = append(out, map[string]any{"id": c.ID, "remote": c.Remote, "tls": c.TLS, "username": c.Username, "uid": c.UID,
			"callsign": c.Callsign, "connected": c.Connected, "lastSeen": c.lastSeen, "in": c.inG, "out": c.outG,
			"rx": c.recv.Load(), "tx": c.sent.Load()})
		c.mu.RUnlock()
	}
	writeJSON(w, 200, out)
}

// ---------- users & groups ----------

func (s *Server) CreateUser(name, password string, admin bool, groups []Membership) error {
	name = strings.TrimSpace(name)
	if !validUsername(name) {
		return fmt.Errorf("user name: 1–64 characters, letters, digits and _ - . @")
	}
	if len(password) < 8 {
		return fmt.Errorf("the password needs at least 8 characters")
	}
	if groups == nil {
		groups = []Membership{{AnonGroup, "IN"}, {AnonGroup, "OUT"}}
	}
	h := hashPassword(password)
	var err error
	s.store.Update(func(st *State) {
		if findUser(st, name) != nil {
			err = fmt.Errorf("user %q already exists", name)
			return
		}
		for _, m := range groups {
			if findGroup(st, m.Group) == nil {
				st.Groups = append(st.Groups, &Group{ID: st.nextID(), Name: m.Group, Created: time.Now()})
			}
		}
		st.Users = append(st.Users, &User{ID: st.nextID(), Username: name, PassHash: h, Admin: admin, Active: true, Created: time.Now(), Groups: groups})
	})
	if err == nil {
		logf("User created: %s%s", name, map[bool]string{true: " (administrator)", false: ""}[admin])
	}
	return err
}

func (s *Server) DeleteUser(name string) error {
	found := false
	s.store.Update(func(st *State) {
		keep := st.Users[:0]
		for _, u := range st.Users {
			if u.Username == name {
				found = true
				continue
			}
			keep = append(keep, u)
		}
		st.Users = keep
		for _, c := range st.Certs {
			if c.Username == name {
				c.Revoked = true
			}
		}
		toks := st.Tokens[:0]
		for _, t := range st.Tokens {
			if t.Username != name {
				toks = append(toks, t)
			}
		}
		st.Tokens = toks
	})
	if !found {
		return fmt.Errorf("user %q does not exist", name)
	}
	s.sessions.dropUser(name)
	s.hub.RefreshGroups()
	logf("User deleted: %s (certificates revoked)", name)
	return nil
}

func (s *Server) CreateGroup(name, desc string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 60 || strings.ContainsAny(name, "<>\"&/") {
		return fmt.Errorf("group name: 1–60 characters")
	}
	var err error
	s.store.Update(func(st *State) {
		if findGroup(st, name) != nil {
			err = fmt.Errorf("group %q already exists", name)
			return
		}
		st.Groups = append(st.Groups, &Group{ID: st.nextID(), Name: name, Description: desc, Created: time.Now()})
	})
	return err
}

func (s *Server) DeleteGroup(name string) error {
	if name == AnonGroup {
		return fmt.Errorf("%s is the default group and stays", AnonGroup)
	}
	found := false
	s.store.Update(func(st *State) {
		keep := st.Groups[:0]
		for _, g := range st.Groups {
			if g.Name == name {
				found = true
				continue
			}
			keep = append(keep, g)
		}
		st.Groups = keep
		for _, u := range st.Users {
			ms := u.Groups[:0]
			for _, m := range u.Groups {
				if m.Group != name {
					ms = append(ms, m)
				}
			}
			u.Groups = ms
		}
	})
	if !found {
		return fmt.Errorf("group %q does not exist", name)
	}
	s.hub.RefreshGroups()
	return nil
}

func (s *Server) apiUsers(w http.ResponseWriter) {
	out := []map[string]any{}
	online := map[string]int{}
	for _, c := range s.hub.Clients() {
		if c.Username != "" {
			online[c.Username]++
		}
	}
	s.store.Read(func(st *State) {
		for _, u := range st.Users {
			certs := 0
			for _, c := range st.Certs {
				if c.Username == u.Username && !c.Revoked {
					certs++
				}
			}
			var devices []string
			for _, e := range st.EUDs {
				if e.Username == u.Username {
					devices = append(devices, e.Callsign)
				}
			}
			out = append(out, map[string]any{"username": u.Username, "admin": u.Admin, "active": u.Active, "created": u.Created,
				"lastLogin": u.LastLogin, "groups": u.Groups, "certs": certs, "devices": devices, "online": online[u.Username]})
		}
	})
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]["username"].(string)) < strings.ToLower(out[j]["username"].(string))
	})
	writeJSON(w, 200, out)
}

func (s *Server) apiCreateUser(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string
		Password string
		Admin    bool
		Groups   []string
	}
	readJSON(r, &b)
	pw := b.Password
	if pw == "" {
		pw = randomPassword(10)
	}
	var ms []Membership
	if len(b.Groups) > 0 {
		for _, g := range b.Groups {
			ms = append(ms, Membership{g, "IN"}, Membership{g, "OUT"})
		}
	}
	if err := s.CreateUser(b.Username, pw, b.Admin, ms); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "password": pw})
}

func (s *Server) apiUpdateUser(w http.ResponseWriter, r *http.Request, name string) {
	var b struct {
		Active   *bool
		Admin    *bool
		Password *string
		Groups   *[]Membership
	}
	readJSON(r, &b)
	newPw := ""
	if b.Password != nil {
		newPw = *b.Password
		if newPw == "" {
			newPw = randomPassword(10)
		}
		if len(newPw) < 8 {
			jsonErr(w, 400, "The password needs at least 8 characters.")
			return
		}
	}
	found := false
	s.store.Update(func(st *State) {
		u := findUser(st, name)
		if u == nil {
			return
		}
		found = true
		if b.Active != nil {
			u.Active = *b.Active
		}
		if b.Admin != nil {
			u.Admin = *b.Admin
		}
		if newPw != "" {
			u.PassHash = hashPassword(newPw)
			u.APIToken = ""
		}
		if b.Groups != nil {
			var ms []Membership
			for _, m := range *b.Groups {
				if m.Direction != "IN" && m.Direction != "OUT" {
					continue
				}
				if findGroup(st, m.Group) == nil {
					st.Groups = append(st.Groups, &Group{ID: st.nextID(), Name: m.Group, Created: time.Now()})
				}
				ms = append(ms, m)
			}
			u.Groups = ms
		}
	})
	if !found {
		jsonErr(w, 404, "User not found.")
		return
	}
	if b.Active != nil && !*b.Active {
		s.sessions.dropUser(name)
	}
	s.hub.RefreshGroups()
	out := map[string]any{"ok": true}
	if newPw != "" {
		out["password"] = newPw
	}
	writeJSON(w, 200, out)
}

// deviceHost: the address devices should use – configured, or the one the browser used.
func (s *Server) deviceHost(r *http.Request) string {
	if h := strings.TrimSpace(r.URL.Query().Get("host")); h != "" {
		return h
	}
	if h := strings.TrimSpace(s.store.Config().PublicHost); h != "" {
		return h
	}
	h := clientHost(r)
	if h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" {
		return s.PublicHost()
	}
	return h
}

func (s *Server) apiPackage(w http.ResponseWriter, r *http.Request, user string) {
	exists := false
	s.store.Read(func(st *State) { exists = findUser(st, user) != nil })
	if !exists {
		jsonErr(w, 404, "User not found.")
		return
	}
	zb, err := s.ConnectionPackage(user, s.deviceHost(r))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	name := strings.NewReplacer(" ", "_", "/", "_").Replace(s.store.Config().ServerName) + "-" + user + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, time.Now(), bytes.NewReader(zb))
}

// apiEnroll creates an enrollment token and the QR codes for ATAK and iTAK.
func (s *Server) apiEnroll(w http.ResponseWriter, r *http.Request, user string) {
	var b struct {
		MaxUses int
		Hours   int
	}
	readJSON(r, &b)
	if b.Hours <= 0 {
		b.Hours = 72
	}
	if b.MaxUses < 0 {
		b.MaxUses = 0
	}
	if b.MaxUses == 0 {
		b.MaxUses = 3
	}
	tok := randomPassword(16)
	ok := false
	s.store.Update(func(st *State) {
		if u := findUser(st, user); u != nil && u.Active {
			ok = true
			st.Tokens = append(st.Tokens, &EnrollToken{Token: tok, Username: user, MaxUses: b.MaxUses, Expires: time.Now().Add(time.Duration(b.Hours) * time.Hour), Created: time.Now()})
		}
	})
	if !ok {
		jsonErr(w, 404, "User not found or blocked.")
		return
	}
	host := s.deviceHost(r)
	atak := s.atakQRString(host, user, tok)
	itak := s.itakQRString(host)
	writeJSON(w, 200, map[string]any{
		"host": host, "username": user, "token": tok, "expires": time.Now().Add(time.Duration(b.Hours) * time.Hour), "maxUses": b.MaxUses,
		"atak": atak, "atakQR": qrDataURL(atak), "itak": itak, "itakQR": qrDataURL(itak),
		"sslPort": s.ports.SSL, "enrollPort": s.ports.Enroll,
	})
}

// ---------- federation ----------

func (s *Server) apiFederation(w http.ResponseWriter, r *http.Request, seg []string) {
	m := r.Method
	route := strings.Join(seg, "/")
	switch {
	case route == "" && m == "GET":
		var invites []FedInvite
		s.store.Read(func(st *State) {
			for _, inv := range st.FedInvites {
				if time.Now().Before(inv.Expires) {
					invites = append(invites, *inv)
				}
			}
		})
		cfg := s.store.Config()
		writeJSON(w, 200, map[string]any{"links": s.fed.Status(), "invites": invites, "port": s.ports.Fed, "enabled": cfg.FedEnabled,
			"serverName": cfg.ServerName, "serverUid": cfg.ServerUID, "caFingerprint": s.pki.CAFingerprint()})
	case route == "invite" && m == "POST":
		var b struct{ Label string }
		readJSON(r, &b)
		code, err := s.fed.CreateInvite(strings.TrimSpace(b.Label))
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"code": code})
	case route == "join" && m == "POST":
		var b struct{ Code, Address string }
		readJSON(r, &b)
		l, err := s.fed.Join(b.Code, b.Address)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "peerName": l.PeerName})
	case len(seg) == 2 && seg[0] == "links" && m == "PUT":
		var b struct {
			Enabled *bool
			Transit *bool
			Groups  *[]string
		}
		readJSON(r, &b)
		s.store.Update(func(st *State) {
			for _, l := range st.FedLinks {
				if l.ID == seg[1] {
					if b.Enabled != nil {
						l.Enabled = *b.Enabled
					}
					if b.Transit != nil {
						l.Transit = *b.Transit
					}
					if b.Groups != nil {
						l.Groups = *b.Groups
					}
				}
			}
		})
		s.fed.Reconcile()
		writeJSON(w, 200, map[string]any{"ok": true})
	case len(seg) == 2 && seg[0] == "links" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.FedLinks[:0]
			for _, l := range st.FedLinks {
				if l.ID != seg[1] {
					keep = append(keep, l)
				}
			}
			st.FedLinks = keep
		})
		s.fed.Reconcile()
		writeJSON(w, 200, map[string]any{"ok": true})
	case len(seg) == 2 && seg[0] == "invites" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.FedInvites[:0]
			for _, inv := range st.FedInvites {
				if inv.Token != seg[1] {
					keep = append(keep, inv)
				}
			}
			st.FedInvites = keep
		})
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		jsonErr(w, 404, "Unknown request.")
	}
}

// ---------- settings ----------

func (s *Server) settingsView() map[string]any {
	c := s.store.Config()
	return map[string]any{"serverName": c.ServerName, "publicHost": c.PublicHost, "enableTcp": c.EnableTCP, "anonHttp": c.AnonHTTP,
		"certPassword": c.CertPassword, "webCert": c.WebCert, "webKey": c.WebKey, "fedEnabled": c.FedEnabled,
		"sendLatestSa": c.SendLatestSA, "contactMaxAge": c.ContactMaxAge, "dataDir": s.dataDir,
		"videoEnabled": c.VideoEnabled, "videoReadAuth": c.VideoReadAuth, "mediamtxPath": c.MediaMTXPath, "videoFedShare": c.VideoFedShare,
		"lat": c.Lat, "lon": c.Lon, "mqttOn": !c.MQTTOff, "mqttPlain": c.MQTTPlain}
}

func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ServerName    *string
		PublicHost    *string
		EnableTCP     *bool `json:"enableTcp"`
		AnonHTTP      *bool `json:"anonHttp"`
		CertPassword  *string
		WebCert       *string
		WebKey        *string
		FedEnabled    *bool
		SendLatestSA  *bool `json:"sendLatestSa"`
		ContactMaxAge *int
		VideoEnabled  *bool
		VideoReadAuth *bool
		MediaMTXPath  *string `json:"mediamtxPath"`
		VideoFedShare *bool
		Lat, Lon      *float64
		MQTTOn        *bool `json:"mqttOn"`
		MQTTPlain     *bool `json:"mqttPlain"`
	}
	if err := readJSON(r, &b); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if b.CertPassword != nil && len(*b.CertPassword) < 6 {
		jsonErr(w, 400, "Certificate password: at least 6 characters (default atakatak).")
		return
	}
	if b.WebCert != nil && *b.WebCert != "" {
		key := ""
		if b.WebKey != nil {
			key = *b.WebKey
		}
		if err := s.pki.SetWebCert(*b.WebCert, key); err != nil {
			jsonErr(w, 400, "Certificate could not be loaded: "+err.Error())
			return
		}
	} else if b.WebCert != nil {
		s.pki.SetWebCert("", "")
	}
	restart := false
	s.store.Update(func(st *State) {
		c := &st.Config
		if b.ServerName != nil && strings.TrimSpace(*b.ServerName) != "" {
			c.ServerName = strings.TrimSpace(*b.ServerName)
		}
		if b.PublicHost != nil {
			c.PublicHost = strings.TrimSpace(*b.PublicHost)
		}
		if b.EnableTCP != nil && *b.EnableTCP != c.EnableTCP {
			c.EnableTCP = *b.EnableTCP
			restart = true
		}
		if b.AnonHTTP != nil {
			c.AnonHTTP = *b.AnonHTTP
		}
		if b.CertPassword != nil {
			c.CertPassword = *b.CertPassword
		}
		if b.WebCert != nil {
			c.WebCert = strings.TrimSpace(*b.WebCert)
		}
		if b.WebKey != nil {
			c.WebKey = strings.TrimSpace(*b.WebKey)
		}
		if b.FedEnabled != nil {
			c.FedEnabled = *b.FedEnabled
		}
		if b.SendLatestSA != nil {
			c.SendLatestSA = *b.SendLatestSA
		}
		if b.ContactMaxAge != nil && *b.ContactMaxAge > 0 {
			c.ContactMaxAge = *b.ContactMaxAge
		}
		if b.VideoEnabled != nil {
			c.VideoEnabled = *b.VideoEnabled
		}
		if b.VideoReadAuth != nil {
			c.VideoReadAuth = *b.VideoReadAuth
		}
		if b.MediaMTXPath != nil {
			c.MediaMTXPath = strings.TrimSpace(*b.MediaMTXPath)
		}
		if b.VideoFedShare != nil {
			c.VideoFedShare = *b.VideoFedShare
		}
		if b.MQTTOn != nil && *b.MQTTOn == c.MQTTOff {
			c.MQTTOff = !*b.MQTTOn
			restart = true
		}
		if b.MQTTPlain != nil && *b.MQTTPlain != c.MQTTPlain {
			c.MQTTPlain = *b.MQTTPlain
			restart = true
		}
		if b.Lat != nil && b.Lon != nil && *b.Lat >= -90 && *b.Lat <= 90 && *b.Lon >= -180 && *b.Lon <= 180 {
			c.Lat, c.Lon = *b.Lat, *b.Lon
		}
	})
	s.media.Kick()
	go s.pki.ensureServerCert()
	writeJSON(w, 200, map[string]any{"ok": true, "restart": restart})
}

func (s *Server) apiVideo(w http.ResponseWriter, r *http.Request, user string) {
	status, bin, running := s.media.Status()
	host := s.deviceHost(r)
	cfg := s.store.Config()
	feeds := []map[string]any{}
	for _, f := range s.media.Feeds() {
		m := map[string]any{"uid": f.UID, "alias": f.Alias, "path": f.Path, "kind": f.Kind, "source": f.Source, "origin": f.Origin,
			"url": f.URL, "live": f.Live, "readers": f.Readers, "tracks": f.Tracks, "configured": f.Configured, "user": f.User}
		if f.Path != "" {
			m["links"] = s.streamLinks(host, f.Path)
		}
		feeds = append(feeds, m)
	}
	writeJSON(w, 200, map[string]any{
		"enabled": cfg.VideoEnabled, "status": status, "program": bin, "running": running, "version": mediamtxVersion,
		"readAuth": cfg.VideoReadAuth, "fedShare": cfg.VideoFedShare, "host": host, "feeds": feeds,
		"ports":   map[string]int{"rtsp": s.ports.RTSP, "rtmp": s.ports.RTMP, "hls": s.ports.HLS, "webrtc": s.ports.WebRTC, "srt": s.ports.SRT},
		"publish": s.publishLinks(host, "drone-1", user),
	})
}
