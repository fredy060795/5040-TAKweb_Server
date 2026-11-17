package main

// Interfaces the WebTAK app (port 5036) uses on its TAK server, checked with the same requests.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// forgeStyleCSR builds a request like node-forge does: the common name as PrintableString even with "_",
// which Go's own parser refuses.
func forgeStyleCSR(t *testing.T, cn string, key *rsa.PrivateKey) []byte {
	t.Helper()
	type atv struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	rdn := []atv{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte(cn)}}}
	subject, err := asn1.Marshal([][]atv{rdn})
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	info, err := asn1.Marshal(struct {
		Version int
		Subject asn1.RawValue
		PKInfo  asn1.RawValue
		Attrs   asn1.RawValue `asn1:"tag:0"`
	}{0, asn1.RawValue{FullBytes: subject}, asn1.RawValue{FullBytes: spki}, asn1.RawValue{Class: 2, Tag: 0, IsCompound: true}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(info)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	der, err := asn1.Marshal(struct {
		Info   asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: info}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue},
		asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificateRequest(der); err == nil {
		t.Fatal("test request should be refused by Go's strict parser")
	}
	return der
}

func TestWebTAKClientInterfaces(t *testing.T) {
	srv := startServer(t, "Alpha")
	srv.CreateUser("alpha_10", "Alpha-pass-1", false, nil)
	hc := httpClient()
	enroll := fmt.Sprintf("https://127.0.0.1:%d", srv.ports.Enroll)

	// login check without a certificate request (empty body), like OpenTAKServer
	req, _ := http.NewRequest("POST", enroll+"/Marti/api/tls/signClient/", nil)
	req.SetBasicAuth("alpha_10", "Alpha-pass-1")
	if r, err := hc.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("login check: %v %v", r, err)
	}
	req.SetBasicAuth("alpha_10", "wrong")
	if r, _ := hc.Do(req); r.StatusCode != 401 {
		t.Fatal("wrong password accepted")
	}

	// node-forge style request with "_" in a PrintableString
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := base64.StdEncoding.EncodeToString(forgeStyleCSR(t, "alpha_10", key))
	req, _ = http.NewRequest("POST", enroll+"/Marti/api/tls/signClient/v2?clientUid=WEBTAK-1&version=WebTAK", strings.NewReader(body))
	req.SetBasicAuth("alpha_10", "Alpha-pass-1")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enrollment: %v %s", err, b)
	}
	var en map[string]string
	json.NewDecoder(resp.Body).Decode(&en)
	certDER, _ := base64.StdEncoding.DecodeString(en["signedCert"])
	cert := tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
	mc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{cert}}}}
	api := fmt.Sprintf("https://127.0.0.1:%d", srv.ports.HTTPS)
	call := func(method, path string, body io.Reader) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, api+path, body)
		r, err := mc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}

	// device profile after enrollment (ATAK path) with a stored preference
	srv.store.Update(func(s *State) {
		s.Profiles = append(s.Profiles, &Profile{ID: 1, EUDUID: "WEBTAK-1", Key: "locationCallsign", Value: "ALPHA-10", Enrollment: true, Active: true})
	})
	req, _ = http.NewRequest("GET", enroll+"/Marti/api/tls/profile/enrollment?clientUid=WEBTAK-1", nil)
	req.SetBasicAuth("alpha_10", "Alpha-pass-1")
	if r, _ := hc.Do(req); r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/zip" {
		t.Fatalf("enrollment profile: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}

	// Data Sync mission: create, subscribe, mission CoT, read back, files, changes
	if code, b := call("PUT", "/Marti/api/missions/OP-1?creatorUid=WEBTAK-1&description=test&tool=public", nil); code != 201 {
		t.Fatalf("create mission: %d %s", code, b)
	}
	if code, b := call("GET", "/Marti/api/missions?passwordProtected=true&defaultRole=true&tool=public", nil); code != 200 || !strings.Contains(b, `"name":"OP-1"`) {
		t.Fatalf("list: %s", b)
	}
	code, b := call("PUT", "/Marti/api/missions/OP-1/subscription?uid=WEBTAK-1", nil)
	if code != 201 || !strings.Contains(b, `"token"`) {
		t.Fatalf("subscribe: %d %s", code, b)
	}
	sub := dialTCP(t, srv.ports.TCP)
	sub.send(sa("WEBTAK-1", "ALPHA-10")) // the subscriber is online
	other := dialTCP(t, srv.ports.TCP)
	other.send(sa("uid-other", "OTHER"))
	time.Sleep(200 * time.Millisecond)
	other.send(`<event version="2.0" uid="marker-1" type="a-h-G" how="h-g-i-g-o" time="2024-01-01T00:00:00Z" start="2024-01-01T00:00:00Z" stale="2030-01-01T00:00:00Z"><point lat="48.1" lon="11.1" hae="0" ce="9" le="9"/><detail><contact callsign="Enemy 1"/><marti><dest mission="OP-1"/></marti></detail></event>`)
	sub.waitFor("mission CoT at the subscriber", uidIs("marker-1"))
	sub.waitFor("mission change notice", func(e *Event) bool { return e.Type == "t-x-m-c" })
	if code, b := call("GET", "/Marti/api/missions/OP-1/cot", nil); code != 200 || !strings.Contains(b, `uid="marker-1"`) {
		t.Fatalf("mission cot: %s", b)
	}
	pk, _ := srv.packages.Save(strings.NewReader("kml"), Package{Name: "area.kml"}, "")
	if code, b := call("PUT", "/Marti/api/missions/OP-1/contents?creatorUid=WEBTAK-1", bytes.NewReader([]byte(`{"hashes":["`+pk.Hash+`"]}`))); code != 200 || !strings.Contains(b, "area.kml") {
		t.Fatalf("contents: %s", b)
	}
	if code, b := call("GET", "/Marti/api/missions/OP-1?changes=false&logs=false", nil); code != 200 || !strings.Contains(b, `"data":"marker-1"`) || !strings.Contains(b, pk.Hash) {
		t.Fatalf("mission: %s", b)
	}
	if code, b := call("GET", "/Marti/api/missions/OP-1/changes", nil); code != 200 || strings.Count(b, `"ADD_CONTENT"`) != 2 {
		t.Fatalf("changes: %s", b)
	}
	if code, _ := call("DELETE", "/Marti/api/missions/OP-1/subscription?uid=WEBTAK-1", nil); code != 200 {
		t.Fatal("unsubscribe")
	}
	// password protected mission
	call("PUT", "/Marti/api/missions/SECRET?creatorUid=WEBTAK-1&password=pw123", nil)
	if code, _ := call("PUT", "/Marti/api/missions/SECRET/subscription?uid=WEBTAK-1", nil); code != 401 {
		t.Fatalf("subscribed without password: %d", code)
	}
	if code, _ := call("PUT", "/Marti/api/missions/SECRET/subscription?uid=WEBTAK-1&password=pw123", nil); code != 201 {
		t.Fatal("subscribe with password")
	}

	// video list as JSON (configured link feed)
	srv.store.Update(func(s *State) {
		s.Videos = append(s.Videos, &VideoFeed{UID: "v1", Alias: "Cam", URL: "rtsp://10.0.0.5:554/live"})
	})
	if code, b := call("GET", "/Marti/api/video", nil); code != 200 || !strings.Contains(b, `"url":"rtsp://10.0.0.5:554/live"`) {
		t.Fatalf("video json: %s", b)
	}
}

func TestOTSMeshtasticAPI(t *testing.T) {
	srv := startServer(t, "A")
	srv.CreateUser("admin", "admin-pass", true, nil)
	hc := httpClient()
	base := fmt.Sprintf("https://127.0.0.1:%d", srv.ports.HTTPS)
	do := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.SetBasicAuth("admin", "admin-pass")
		r, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, b := do("GET", "/api/meshtastic/generate_psk", ""); code != 200 || !strings.Contains(b, `"psk"`) {
		t.Fatalf("psk: %s", b)
	}
	link := channelURL("LongFast", []byte{1}, "LONG_FAST", "EU_868", true, true, 3, 32)
	if code, b := do("POST", "/api/meshtastic/channel", `{"url":"https://meshtastic.org/e/#x"}`); code != 400 {
		t.Fatalf("unreadable link accepted: %s", b)
	}
	do("POST", "/api/meshtastic/channel", `{"url":"`+link+`"}`)
	// created by name like in OTS: the server makes the link
	if code, b := do("POST", "/api/meshtastic/channel", `{"name":"TAK","psk":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`","modem_preset":"LONG_FAST","lora_region":"EU_868"}`); code != 200 {
		t.Fatalf("by name: %s", b)
	}
	if code, b := do("GET", "/api/meshtastic/channel?per_page=200", ""); code != 200 || !strings.Contains(b, "LongFast") || !strings.Contains(b, `"name":"TAK","psk"`) || !strings.Contains(b, "https://meshtastic.org/e/#") {
		t.Fatalf("list: %s", b)
	}
	if keys := srv.meshKeys(); len(keys["LongFast"].key) != 16 || len(keys["TAK"].key) != 32 {
		t.Fatalf("keys: %v", keys)
	}
	do("DELETE", "/api/meshtastic/channel?url="+url.QueryEscape(link), "")
	if _, b := do("GET", "/api/meshtastic/channel", ""); strings.Contains(b, "LongFast") {
		t.Fatal("not deleted")
	}
}
