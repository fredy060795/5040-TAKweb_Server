package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	sub, _ := fs.Sub(webFS, "web")
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" || strings.HasSuffix(p, "/") {
		p = "index.html"
	}
	if _, err := fs.Stat(sub, p); err != nil {
		p = "index.html" // single page app
	}
	if p == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFileFS(w, r, sub, p)
}

func defaultDataDir() string {
	if d := os.Getenv("WTS_DATA"); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		// "go run" builds into a temp folder – use the working directory then
		if !strings.Contains(dir, "go-build") {
			return filepath.Join(dir, "takdata")
		}
	}
	return "takdata"
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			exitOn(install(os.Args[2:]))
			return
		case "uninstall":
			exitOn(uninstall(os.Args[2:]))
			return
		case "reset-password":
			exitOn(resetPassword(os.Args[2:]))
			return
		case "version", "-version", "--version":
			fmt.Println("WebTAK Server", Version)
			return
		}
	}
	ports := DefaultPorts()
	dataDir := flag.String("data", defaultDataDir(), "data directory (settings, users, certificates, data packages)")
	bind := flag.String("bind", "", "listen only on this IP address (default: all)")
	service := flag.Bool("service", false, "running as a background service (no browser, no prompts)")
	noBrowser := flag.Bool("no-browser", false, "do not open the web interface on start")
	flag.IntVar(&ports.TCP, "port-tcp", ports.TCP, "CoT TCP port (unencrypted)")
	flag.IntVar(&ports.SSL, "port-ssl", ports.SSL, "CoT SSL port")
	flag.IntVar(&ports.HTTPS, "port-https", ports.HTTPS, "HTTPS port (web interface, Marti API)")
	flag.IntVar(&ports.HTTP, "port-http", ports.HTTP, "HTTP port (Marti API, web interface for this computer)")
	flag.IntVar(&ports.Enroll, "port-enroll", ports.Enroll, "certificate enrollment port")
	flag.IntVar(&ports.Fed, "port-fed", ports.Fed, "federation port")
	flag.IntVar(&ports.MQTT, "port-mqtt", ports.MQTT, "MQTT port with TLS for Meshtastic radios")
	flag.IntVar(&ports.MQTTPlain, "port-mqtt-plain", ports.MQTTPlain, "MQTT port without TLS (only if switched on in the settings)")
	flag.IntVar(&ports.RTSP, "port-rtsp", ports.RTSP, "video: RTSP port (-1 = off)")
	flag.IntVar(&ports.RTMP, "port-rtmp", ports.RTMP, "video: RTMP port (-1 = off)")
	flag.IntVar(&ports.HLS, "port-hls", ports.HLS, "video: HLS port (-1 = off)")
	flag.IntVar(&ports.WebRTC, "port-webrtc", ports.WebRTC, "video: WebRTC port (-1 = off)")
	flag.IntVar(&ports.WebRTCUDP, "port-webrtc-udp", ports.WebRTCUDP, "video: WebRTC UDP port")
	flag.IntVar(&ports.SRT, "port-srt", ports.SRT, "video: SRT port, UDP (-1 = off)")
	flag.IntVar(&ports.RTP, "port-rtp", ports.RTP, "video: RTP port, UDP (RTCP = +1; -1 = RTSP over TCP only)")
	flag.IntVar(&ports.MediaAPI, "port-media-api", ports.MediaAPI, "video: MediaMTX control port on 127.0.0.1")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime)
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fatal("Cannot create the data directory %s: %v", *dataDir, err)
	}
	if f, err := os.OpenFile(filepath.Join(*dataDir, "server.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		if st, _ := f.Stat(); st != nil && st.Size() > 20<<20 {
			f.Truncate(0)
		}
		log.SetOutput(multiWriter{os.Stdout, f})
	}
	logf("WebTAK Server %s starting (%s/%s), data: %s", Version, runtime.GOOS, runtime.GOARCH, *dataDir)
	srv, err := NewServer(*dataDir, ports)
	if err != nil {
		fatal("Start failed: %v", err)
	}
	srv.bindAddr = *bind
	if err := srv.Start(); err != nil {
		fatal("Start failed: %v", err)
	}
	printBanner(srv)
	if !*service && !*noBrowser {
		go func() {
			time.Sleep(time.Second)
			if srv.ports.HTTP > 0 {
				openBrowser(fmt.Sprintf("http://localhost:%d/", srv.ports.HTTP))
			} else {
				openBrowser(fmt.Sprintf("https://localhost:%d/", srv.ports.HTTPS))
			}
		}()
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	logf("Stopping …")
	srv.Close()
}

type multiWriter []interface{ Write([]byte) (int, error) }

func (m multiWriter) Write(p []byte) (int, error) {
	for _, w := range m {
		w.Write(p)
	}
	return len(p), nil
}

func printBanner(s *Server) {
	cfg := s.store.Config()
	host := s.PublicHost()
	fmt.Println()
	fmt.Println("  ===========================================================")
	fmt.Printf("   WebTAK Server %s is running – %s\n", Version, cfg.ServerName)
	fmt.Println("  ===========================================================")
	if s.ports.HTTP > 0 {
		fmt.Printf("   Web interface (this computer):  http://localhost:%d/\n", s.ports.HTTP)
	}
	fmt.Printf("   Web interface (other devices):  https://%s:%d/\n", host, s.ports.HTTPS)
	if !cfg.SetupDone {
		fmt.Println("   -> Open the web interface and finish the setup (admin password).")
	}
	fmt.Printf("   TAK devices: %s  SSL %d", host, s.ports.SSL)
	if s.ports.TCP > 0 {
		fmt.Printf("  |  TCP %d", s.ports.TCP)
	}
	fmt.Printf("  |  enrollment %d  |  federation %d\n", s.ports.Enroll, s.ports.Fed)
	fmt.Println("   Close this window or press Ctrl+C to stop the server.")
	fmt.Println()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return // headless (e.g. Raspberry Pi over SSH)
		}
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func fatal(format string, args ...any) {
	logf(format, args...)
	if runtime.GOOS == "windows" {
		fmt.Println("\nPress Enter to close.")
		fmt.Scanln()
	}
	os.Exit(1)
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		if runtime.GOOS == "windows" {
			fmt.Println("\nPress Enter to close.")
			fmt.Scanln()
		}
		os.Exit(1)
	}
}

// reset-password [-data DIR] USER – for a forgotten admin password (stop the server first, it would
// overwrite the change when it saves).
func resetPassword(args []string) error {
	fl := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dataDir := fl.String("data", installedDataDir(), "data directory")
	fl.Parse(args)
	user := fl.Arg(0)
	if user == "" {
		return fmt.Errorf("usage: webtak-server reset-password [-data DIR] USERNAME")
	}
	st, err := OpenStore(*dataDir)
	if err != nil {
		return err
	}
	pw := randomPassword(12)
	found := false
	st.Update(func(s *State) {
		if u := findUser(s, user); u != nil {
			u.PassHash, u.Active, found = hashPassword(pw), true, true
		}
	})
	st.Close()
	if !found {
		return fmt.Errorf("user %q not found in %s", user, *dataDir)
	}
	fmt.Printf("New password for %s: %s\nStart the server again now.\n", user, pw)
	return nil
}
