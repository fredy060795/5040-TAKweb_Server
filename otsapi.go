package main

// OpenTAKServer-compatible web API (/api/...): tools written for OTS (e.g. WebTAK on port 5036) can
// manage this server the same way – login, users, roles, groups, devices, ATAK QR, truststore,
// device profiles, missions, video (MediaMTX) and Meshtastic channels (MQTT, meshtastic.go).

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func otsOK(w http.ResponseWriter, msg string) {
	writeJSON(w, 200, map[string]any{"success": true, "message": msg})
}

func otsErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"success": false, "error": msg})
}

// paginate: OTS list format {results, total, current_page, per_page, total_pages}
func paginate(r *http.Request, items []map[string]any) map[string]any {
	if items == nil {
		items = []map[string]any{}
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if per <= 0 {
		per = 10
	}
	if page <= 0 {
		page = 1
	}
	total := len(items)
	start := (page - 1) * per
	if start > total {
		start = total
	}
	end := start + per
	if end > total {
		end = total
	}
	return map[string]any{"results": items[start:end], "total": total, "current_page": page, "per_page": per, "total_pages": (total + per - 1) / per}
}

func otsTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func (s *Server) otsUserJSON(st *State, u *User) map[string]any {
	roles := []map[string]any{{"name": "user"}}
	if u.Admin {
		roles = []map[string]any{{"name": "administrator"}}
	}
	gm := []map[string]any{}
	for _, m := range u.Groups {
		gm = append(gm, map[string]any{"group_name": m.Group, "direction": m.Direction, "enabled": true})
	}
	euds := []map[string]any{}
	for _, e := range st.EUDs {
		if e.Username == u.Username {
			euds = append(euds, s.otsEUD(e))
		}
	}
	return map[string]any{"id": u.ID, "username": u.Username, "active": u.Active, "roles": roles,
		"last_login_at": otsTime(u.PrevLogin), "current_login_at": otsTime(u.LastLogin), "group_memberships": gm, "euds": euds}
}

func (s *Server) otsEUD(e *EUD) map[string]any {
	return map[string]any{"uid": e.UID, "callsign": e.Callsign, "device": e.Device, "os": e.OS, "platform": e.Platform,
		"version": e.Version, "phone_number": e.Phone, "last_event_time": otsTime(e.LastEventTime), "last_status": e.LastStatus,
		"username": e.Username, "team": e.Team, "team_role": e.Role}
}

func (s *Server) handleOTSAPI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimSuffix(r.URL.Path, "/")
	q := r.URL.Query()
	m := r.Method

	if p == "/api/login" && m == "POST" {
		var b struct{ Username, Password string }
		readJSON(r, &b)
		if !s.checkLogin(b.Username, b.Password, false) {
			time.Sleep(500 * time.Millisecond)
			writeJSON(w, 400, map[string]any{"meta": map[string]any{"code": 400}, "response": map[string]any{"errors": []string{"Invalid username or password"}}})
			return
		}
		var tok string
		var uid int
		s.store.Update(func(st *State) {
			u := findUser(st, b.Username)
			if u.APIToken == "" {
				u.APIToken = randomHex(24)
			}
			u.PrevLogin, u.LastLogin = u.LastLogin, time.Now()
			tok, uid = u.APIToken, u.ID
		})
		s.setSessionCookie(w, r, b.Username)
		writeJSON(w, 200, map[string]any{"meta": map[string]any{"code": 200}, "response": map[string]any{
			"user": map[string]any{"id": uid, "username": b.Username, "authentication_token": tok}, "csrf_token": randomHex(16)}})
		return
	}
	if p == "/api/health" {
		writeJSON(w, 200, map[string]any{"status": "healthy"})
		return
	}

	id := s.who(r)
	if id == nil {
		otsErr(w, 401, "Authentication required")
		return
	}
	if p == "/api/truststore" {
		b, _ := s.pki.TrustStoreP12(s.store.Config().CertPassword)
		w.Header().Set("Content-Type", "application/x-pkcs12")
		w.Header().Set("Content-Disposition", `attachment; filename="truststore-root.p12"`)
		w.Write(b)
		return
	}
	if p == "/api/status" {
		var users, euds int
		s.store.Read(func(st *State) { users, euds = len(st.Users), len(st.EUDs) })
		writeJSON(w, 200, map[string]any{"ots_version": "WebTAK-Server " + Version, "ots_uptime": int(time.Since(s.started).Seconds()),
			"ots_start_time": otsTime(s.started), "tcp": s.ports.TCP > 0, "ssl": s.ports.SSL > 0, "online_euds": len(s.hub.Clients()),
			"users": users, "euds": euds, "cot_router": true})
		return
	}
	// like OTS: video streams can be managed by every logged-in user
	videoAPI := p == "/api/video_streams" || p == "/api/videos" || strings.HasPrefix(p, "/api/mediamtx/stream/")
	if !id.Admin && !videoAPI {
		otsErr(w, 403, "Administrator role required")
		return
	}

	type userBody struct {
		Username        string   `json:"username"`
		Password        string   `json:"password"`
		ConfirmPassword string   `json:"confirm_password"`
		NewPassword     string   `json:"new_password"`
		Roles           []string `json:"roles"`
	}
	switch {
	case p == "/api/user/add" && m == "POST":
		var b userBody
		readJSON(r, &b)
		if b.ConfirmPassword != "" && b.ConfirmPassword != b.Password {
			otsErr(w, 400, "Passwords do not match")
			return
		}
		if err := s.CreateUser(b.Username, b.Password, contains(b.Roles, "administrator"), nil); err != nil {
			otsErr(w, 400, err.Error())
			return
		}
		otsOK(w, "User created")
	case p == "/api/user/delete" && m == "POST":
		var b userBody
		readJSON(r, &b)
		if err := s.DeleteUser(b.Username); err != nil {
			otsErr(w, 400, err.Error())
			return
		}
		otsOK(w, "User deleted")
	case (p == "/api/user/activate" || p == "/api/user/deactivate") && m == "POST":
		var b userBody
		readJSON(r, &b)
		on := p == "/api/user/activate"
		found := false
		s.store.Update(func(st *State) {
			if u := findUser(st, b.Username); u != nil {
				u.Active, found = on, true
			}
		})
		if !found {
			otsErr(w, 400, "User does not exist")
			return
		}
		if !on {
			s.sessions.dropUser(b.Username)
		}
		s.hub.RefreshGroups()
		otsOK(w, "OK")
	case p == "/api/user/password/reset" && m == "POST":
		var b userBody
		readJSON(r, &b)
		if len(b.NewPassword) < 8 {
			otsErr(w, 400, "Password too short (at least 8 characters)")
			return
		}
		h := hashPassword(b.NewPassword)
		found := false
		s.store.Update(func(st *State) {
			if u := findUser(st, b.Username); u != nil {
				u.PassHash, u.APIToken, found = h, "", true
			}
		})
		if !found {
			otsErr(w, 400, "User does not exist")
			return
		}
		otsOK(w, "Password reset")
	case p == "/api/user/role" && m == "POST":
		var b userBody
		readJSON(r, &b)
		s.store.Update(func(st *State) {
			if u := findUser(st, b.Username); u != nil {
				u.Admin = contains(b.Roles, "administrator")
			}
		})
		otsOK(w, "Roles updated")
	case p == "/api/users" || p == "/api/users/all":
		var list []map[string]any
		s.store.Read(func(st *State) {
			for _, u := range st.Users {
				if n := q.Get("username"); n != "" && !strings.Contains(strings.ToLower(u.Username), strings.ToLower(n)) {
					continue
				}
				list = append(list, s.otsUserJSON(st, u))
			}
		})
		if p == "/api/users/all" {
			if list == nil {
				list = []map[string]any{}
			}
			writeJSON(w, 200, list)
			return
		}
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/users/groups":
		var list []map[string]any
		s.store.Read(func(st *State) {
			if u := findUser(st, q.Get("username")); u != nil {
				for _, mb := range u.Groups {
					list = append(list, map[string]any{"group_name": mb.Group, "direction": mb.Direction, "enabled": true})
				}
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/groups" && m == "GET":
		var list []map[string]any
		s.store.Read(func(st *State) {
			for _, g := range st.Groups {
				list = append(list, map[string]any{"id": g.ID, "name": g.Name, "description": g.Description, "created": otsTime(g.Created),
					"type": "SYSTEM", "bitpos": g.ID, "active": true})
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/groups" && m == "POST":
		var b struct{ Name, Description string }
		readJSON(r, &b)
		if err := s.CreateGroup(b.Name, b.Description); err != nil {
			otsErr(w, 400, err.Error())
			return
		}
		otsOK(w, "Group created")
	case p == "/api/groups" && m == "PUT":
		var b struct {
			Users     []string `json:"users"`
			GroupName string   `json:"group_name"`
			Direction string   `json:"direction"`
		}
		readJSON(r, &b)
		if b.Direction != "IN" && b.Direction != "OUT" {
			otsErr(w, 400, "direction must be IN or OUT")
			return
		}
		errMsg := ""
		s.store.Update(func(st *State) {
			if findGroup(st, b.GroupName) == nil {
				errMsg = "Group does not exist"
				return
			}
			for _, name := range b.Users {
				u := findUser(st, name)
				if u == nil {
					continue
				}
				have := false
				for _, mb := range u.Groups {
					have = have || (mb.Group == b.GroupName && mb.Direction == b.Direction)
				}
				if !have {
					u.Groups = append(u.Groups, Membership{b.GroupName, b.Direction})
				}
			}
		})
		if errMsg != "" {
			otsErr(w, 400, errMsg)
			return
		}
		s.hub.RefreshGroups()
		otsOK(w, "Users added to group")
	case p == "/api/groups" && m == "DELETE":
		if err := s.DeleteGroup(q.Get("group_name")); err != nil {
			otsErr(w, 400, err.Error())
			return
		}
		otsOK(w, "Group deleted")
	case p == "/api/groups/members" && m == "DELETE":
		s.store.Update(func(st *State) {
			if u := findUser(st, q.Get("username")); u != nil {
				keep := u.Groups[:0]
				for _, mb := range u.Groups {
					if !(mb.Group == q.Get("group_name") && (q.Get("direction") == "" || mb.Direction == q.Get("direction"))) {
						keep = append(keep, mb)
					}
				}
				u.Groups = keep
			}
		})
		s.hub.RefreshGroups()
		otsOK(w, "Removed from group")
	case p == "/api/eud":
		var list []map[string]any
		s.store.Read(func(st *State) {
			for _, e := range st.EUDs {
				if n := q.Get("username"); n != "" && e.Username != n {
					continue
				}
				if c := q.Get("callsign"); c != "" && !strings.EqualFold(e.Callsign, c) {
					continue
				}
				list = append(list, s.otsEUD(e))
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/atak_qr_string":
		var b struct {
			Username string `json:"username"`
			Max      int    `json:"max"`
			Exp      int64  `json:"exp"`
		}
		readJSON(r, &b)
		if b.Username == "" {
			b.Username = id.User
		}
		tok := randomPassword(16)
		exp := time.Now().Add(30 * 24 * time.Hour)
		if b.Exp > 0 {
			exp = time.Unix(b.Exp, 0)
		}
		ok := false
		s.store.Update(func(st *State) {
			if u := findUser(st, b.Username); u != nil {
				ok = true
				st.Tokens = append(st.Tokens, &EnrollToken{Token: tok, Username: b.Username, MaxUses: b.Max, Expires: exp, Created: time.Now()})
			}
		})
		if !ok {
			otsErr(w, 400, "User does not exist")
			return
		}
		writeJSON(w, 200, map[string]any{"qr_string": s.atakQRString(s.deviceHost(r), b.Username, tok)})
	case p == "/api/profiles" && m == "GET":
		var list []map[string]any
		s.store.Read(func(st *State) {
			for _, pr := range st.Profiles {
				list = append(list, map[string]any{"id": pr.ID, "eud_uid": pr.EUDUID, "preference_key": pr.Key, "preference_value": pr.Value,
					"value_class": pr.ValueClass, "enrollment": pr.Enrollment, "connection": pr.Connection, "active": pr.Active})
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/profiles" && m == "POST":
		var b struct {
			Key        string `json:"preference_key"`
			Value      string `json:"preference_value"`
			ValueClass string `json:"value_class"`
			Enrollment bool   `json:"enrollment"`
			Connection bool   `json:"connection"`
			Active     *bool  `json:"active"`
			EUDUID     string `json:"eud_uid"`
		}
		readJSON(r, &b)
		if b.Key == "" {
			otsErr(w, 400, "preference_key missing")
			return
		}
		s.store.Update(func(st *State) {
			for _, pr := range st.Profiles {
				if pr.Key == b.Key && pr.EUDUID == b.EUDUID {
					pr.Value, pr.ValueClass, pr.Enrollment, pr.Connection = b.Value, b.ValueClass, b.Enrollment, b.Connection
					pr.Active = b.Active == nil || *b.Active
					return
				}
			}
			st.Profiles = append(st.Profiles, &Profile{ID: st.nextID(), EUDUID: b.EUDUID, Key: b.Key, Value: b.Value, ValueClass: b.ValueClass,
				Enrollment: b.Enrollment, Connection: b.Connection, Active: b.Active == nil || *b.Active})
		})
		otsOK(w, "Profile saved")
	case p == "/api/missions" && m == "GET":
		var list []map[string]any
		s.store.Update(func(st *State) {
			for _, ms := range st.Missions {
				normalizeMission(ms)
				list = append(list, s.otsMissionJSON(ms))
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/missions" && (m == "POST" || m == "PUT"):
		var b struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			CreatorUID  string `json:"creator_uid"`
			Tool        string `json:"tool"`
			Password    string `json:"password"`
			Groups      []any  `json:"groups"`
			DefaultRole string `json:"default_role"`
		}
		readJSON(r, &b)
		if strings.TrimSpace(b.Name) == "" {
			otsErr(w, 400, "Mission name missing")
			return
		}
		s.store.Update(func(st *State) {
			groups := []string{}
			for _, g := range b.Groups { // OTS sends group ids, names are accepted too
				switch v := g.(type) {
				case string:
					groups = append(groups, v)
				case float64:
					for _, gr := range st.Groups {
						if gr.ID == int(v) {
							groups = append(groups, gr.Name)
						}
					}
				}
			}
			for _, ms := range st.Missions {
				if ms.Name == b.Name {
					ms.Groups = groups
					if m == "POST" {
						ms.Description, ms.DefaultRole = b.Description, b.DefaultRole
					}
					return
				}
			}
			nm := &Mission{Name: b.Name, Description: b.Description, CreatorUID: b.CreatorUID,
				Tool: orDefault(b.Tool, "public"), Password: b.Password, Groups: groups, DefaultRole: b.DefaultRole, Created: time.Now()}
			normalizeMission(nm) // hashes the password
			nm.addChange(&MissionChange{Type: "CREATE_MISSION", Time: time.Now(), CreatorUID: b.CreatorUID})
			st.Missions = append(st.Missions, nm)
		})
		otsOK(w, "Mission saved")
	case p == "/api/missions" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.Missions[:0]
			for _, ms := range st.Missions {
				if ms.Name != q.Get("name") {
					keep = append(keep, ms)
				}
			}
			st.Missions = keep
		})
		otsOK(w, "Mission deleted")
	case p == "/api/video_streams" || p == "/api/videos":
		writeJSON(w, 200, paginate(r, s.otsVideoStreams(r)))
	case (p == "/api/mediamtx/stream/add" && m == "POST") || (p == "/api/mediamtx/stream/update" && m == "PATCH"):
		var b struct {
			Path   string `json:"path"`
			Source string `json:"source"`
		}
		readJSON(r, &b)
		if err := s.SaveStream(b.Path, b.Source, "", id.User, strings.HasSuffix(p, "update")); err != nil {
			otsErr(w, 400, err.Error())
			return
		}
		otsOK(w, "Stream saved")
	case p == "/api/mediamtx/stream/delete" && m == "DELETE":
		if !id.Admin && !s.streamOwnedBy(q.Get("path"), id.User) {
			otsErr(w, 403, "Only administrators can delete streams of other users")
			return
		}
		if !s.DeleteStream(q.Get("path")) {
			otsErr(w, 400, "Path not found")
			return
		}
		otsOK(w, "Stream deleted")
	case p == "/api/meshtastic/generate_psk":
		writeJSON(w, 200, map[string]any{"psk": base64.StdEncoding.EncodeToString(randomBytes(32))})
	case p == "/api/meshtastic/channel" && m == "GET":
		var list []map[string]any
		s.store.Read(func(st *State) {
			for _, c := range st.Mesh {
				item := map[string]any{}
				json.Unmarshal([]byte(c.Data), &item)
				item["id"], item["name"], item["url"], item["psk"] = c.ID, c.Name, c.URL, c.PSK
				list = append(list, item)
			}
		})
		writeJSON(w, 200, paginate(r, list))
	case p == "/api/meshtastic/channel" && m == "POST":
		// channels: their keys open what radios send over MQTT (meshtastic.go); WebTAK sets radios to the link
		var b map[string]any
		readJSON(r, &b)
		name, _ := b["name"].(string)
		u, _ := b["url"].(string)
		psk, _ := b["psk"].(string)
		if strings.TrimSpace(name) == "" && strings.TrimSpace(u) == "" {
			otsErr(w, 400, "Channel name or URL missing")
			return
		}
		if strings.TrimSpace(u) == "" { // like OTS: make the channel link from the settings
			key, err := base64.StdEncoding.DecodeString(psk)
			if err != nil || (len(key) != 0 && len(key) != 1 && len(key) != 16 && len(key) != 32) {
				otsErr(w, 400, "PSK: base64, 1, 16 or 32 bytes")
				return
			}
			str := func(k, def string) string {
				v, _ := b[k].(string)
				if v == "" {
					return def
				}
				return v
			}
			flag := func(k string) bool { v, ok := b[k].(bool); return !ok || v }
			num := func(k string, def int) int {
				if v, ok := b[k].(float64); ok {
					return int(v)
				}
				return def
			}
			u = channelURL(name, key, str("modem_preset", "LONG_FAST"), str("lora_region", "EU_868"), flag("uplink_enabled"), flag("downlink_enabled"),
				num("lora_hop_limit", 3), num("position_precision", 32))
			b["url"] = u
		} else if names, psks, _, err := parseChannelURL(u); err != nil || len(names) == 0 {
			otsErr(w, 400, "Channel link not readable")
			return
		} else if strings.TrimSpace(name) == "" {
			name, psk = names[0], base64.StdEncoding.EncodeToString(psks[0])
		}
		dup := false
		s.store.Read(func(st *State) {
			for _, c := range st.Mesh {
				dup = dup || c.URL == u
			}
		})
		if dup {
			otsErr(w, 400, "Channel already exists")
			return
		}
		data, _ := json.Marshal(b)
		s.store.Update(func(st *State) {
			st.Mesh = append(st.Mesh, &MeshChannel{ID: st.nextID(), Name: name, URL: u, PSK: psk, Data: string(data), Created: time.Now()})
		})
		otsOK(w, "Channel saved")
	case p == "/api/meshtastic/channel" && m == "DELETE":
		s.store.Update(func(st *State) {
			keep := st.Mesh[:0]
			for _, c := range st.Mesh {
				if c.URL != q.Get("url") {
					keep = append(keep, c)
				}
			}
			st.Mesh = keep
		})
		otsOK(w, "Channel deleted")
	default:
		otsErr(w, 404, "Not supported by WebTAK Server: "+p)
	}
}

// otsVideoStreams: streams in the format of OTS /api/video_streams.
func (s *Server) otsVideoStreams(r *http.Request) []map[string]any {
	host := clientHost(r)
	var out []map[string]any
	for _, f := range s.media.Feeds() {
		if f.Path == "" {
			continue
		}
		settings, _ := json.Marshal(map[string]any{"source": f.Source, "sourceOnDemand": f.Source != "", "record": false})
		links := s.streamLinks(host, f.Path)
		out = append(out, map[string]any{"path": f.Path, "alias": f.Alias, "uid": f.UID, "protocol": "rtsp", "port": s.ports.RTSP,
			"ready": f.Live, "username": f.User, "mediamtx_settings": string(settings), "source": f.Source, "record": false,
			"rtsp_link": links["rtsp"], "hls_link": links["hls"], "webrtc_link": links["webrtc"], "kind": f.Kind,
			"network_timeout": 10000, "rtsp_reliable": 1, "rover_port": -1, "ignore_embedded_klv": false})
	}
	return out
}
