package main

// "install" / "uninstall": run the server in the background, start it with the computer and open
// the firewall – one command (Windows: Install.bat, Linux/Raspberry Pi: install.sh).

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	winTask     = "WebTAK Server"
	linuxUnit   = "/etc/systemd/system/webtak-server.service"
	linuxBin    = "/usr/local/bin/webtak-server"
	linuxData   = "/var/lib/webtak-server"
	allTCPPorts = "8088,8089,8443,8080,8446,9000,8883"
	videoPorts  = "8554/tcp,1935/tcp,8888/tcp,8889/tcp,8890/udp,8189/udp,8000:8001/udp"
)

func winDirs() (bin, data string) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pf, "WebTAK Server"), filepath.Join(pd, "WebTAK Server")
}

func installedDataDir() string {
	switch runtime.GOOS {
	case "windows":
		_, d := winDirs()
		if _, err := os.Stat(filepath.Join(d, "state.json")); err == nil {
			return d
		}
	case "linux":
		if _, err := os.Stat(filepath.Join(linuxData, "state.json")); err == nil {
			return linuxData
		}
	}
	return defaultDataDir()
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if a, b := filepath.Clean(src), filepath.Clean(dst); strings.EqualFold(a, b) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

// copyDir copies the portable data folder into the installed location (first install only).
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if info.Name() == "server.log" {
			return nil
		}
		return copyFile(p, target, 0o600)
	})
}

func install(args []string) error {
	fl := flag.NewFlagSet("install", flag.ExitOnError)
	noBrowser := fl.Bool("no-browser", false, "do not open the web interface")
	fl.Parse(args)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	portable := filepath.Join(filepath.Dir(exe), "takdata")
	switch runtime.GOOS {
	case "windows":
		return installWindows(exe, portable, *noBrowser)
	case "linux":
		return installLinux(exe, portable)
	}
	return errors.New("install is available on Windows and Linux; on this system just start the program")
}

func uninstall(args []string) error {
	fl := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fl.Bool("purge", false, "also delete all data (users, certificates, data packages)")
	fl.Parse(args)
	switch runtime.GOOS {
	case "windows":
		bin, data := winDirs()
		exec.Command("schtasks", "/End", "/TN", winTask).Run()
		exec.Command("schtasks", "/Delete", "/F", "/TN", winTask).Run()
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winTask).Run()
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winTask+" video").Run()
		time.Sleep(2 * time.Second)
		os.RemoveAll(bin)
		if *purge {
			os.RemoveAll(data)
		}
		fmt.Println("WebTAK Server was removed." + map[bool]string{true: "", false: " Your data is still in " + data}[*purge])
	case "linux":
		if os.Geteuid() != 0 {
			return errors.New("please run with sudo")
		}
		exec.Command("systemctl", "disable", "--now", "webtak-server").Run()
		os.Remove(linuxUnit)
		exec.Command("systemctl", "daemon-reload").Run()
		os.Remove(linuxBin)
		if *purge {
			os.RemoveAll(linuxData)
		}
		fmt.Println("WebTAK Server was removed." + map[bool]string{true: "", false: " Your data is still in " + linuxData}[*purge])
	default:
		return errors.New("nothing to uninstall on this system")
	}
	return nil
}

const winTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>WebTAK Server – TAK server for ATAK, iTAK and WinTAK</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>%s</Command><Arguments>-service -data "%s"</Arguments></Exec></Actions>
</Task>`

func installWindows(exe, portable string, noBrowser bool) error {
	if err := exec.Command("net", "session").Run(); err != nil {
		return errors.New("administrator rights are needed – right-click Install.bat and choose \"Run as administrator\"")
	}
	binDir, dataDir := winDirs()
	target := filepath.Join(binDir, "webtak-server.exe")
	fmt.Println("Installing WebTAK Server …")
	exec.Command("schtasks", "/End", "/TN", winTask).Run()
	time.Sleep(time.Second)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	if err := copyFile(exe, target, 0o755); err != nil {
		return fmt.Errorf("copy program: %w (is the server still running? close its window first)", err)
	}
	// video server (MediaMTX) shipped in the zip next to webtak-server.exe
	if mtx := filepath.Join(filepath.Dir(exe), "mediamtx.exe"); fileExists(mtx) {
		if err := copyFile(mtx, filepath.Join(binDir, "mediamtx.exe"), 0o755); err != nil {
			fmt.Println("WARNING: video server not copied:", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "state.json")); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(portable, "state.json")); err == nil {
			fmt.Println("Taking over the data of the portable version from", portable)
			if err := copyDir(portable, dataDir); err != nil {
				return err
			}
		}
	}
	os.MkdirAll(dataDir, 0o700)
	fmt.Println("Opening the Windows firewall …")
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winTask).Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+winTask+" video").Run()
	if err := run("netsh", "advfirewall", "firewall", "add", "rule", "name="+winTask, "dir=in", "action=allow",
		"program="+target, "enable=yes", "profile=any"); err != nil {
		fmt.Println("WARNING:", err)
	}
	// the video server is its own program – bundled, or downloaded later into the data folder
	for _, mtx := range []string{filepath.Join(binDir, "mediamtx.exe"), filepath.Join(dataDir, "mediamtx", "mediamtx.exe")} {
		run("netsh", "advfirewall", "firewall", "add", "rule", "name="+winTask+" video", "dir=in", "action=allow",
			"program="+mtx, "enable=yes", "profile=any")
	}
	fmt.Println("Registering the background service (starts with Windows) …")
	xmlPath := filepath.Join(os.TempDir(), "webtak-server-task.xml")
	// schtasks expects the task XML as UTF-16 with byte order mark
	u := utf16.Encode([]rune(fmt.Sprintf(winTaskXML, xmlEscape(target), xmlEscape(dataDir))))
	content := []byte{0xFF, 0xFE}
	for _, c := range u {
		content = append(content, byte(c), byte(c>>8))
	}
	if err := os.WriteFile(xmlPath, content, 0o600); err != nil {
		return err
	}
	defer os.Remove(xmlPath)
	if err := run("schtasks", "/Create", "/F", "/TN", winTask, "/XML", xmlPath); err != nil {
		return err
	}
	if err := run("schtasks", "/Run", "/TN", winTask); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("Done! WebTAK Server now runs in the background and starts with Windows.")
	fmt.Println("Web interface: http://localhost:8080/")
	fmt.Println("Data folder:  ", dataDir)
	if !noBrowser {
		time.Sleep(3 * time.Second)
		openBrowser("http://localhost:8080/")
	}
	return nil
}

const linuxUnitFile = `[Unit]
Description=WebTAK Server (TAK server for ATAK, iTAK, WinTAK)
After=network-online.target
Wants=network-online.target

[Service]
User=webtak
Group=webtak
ExecStart=%s -service -data %s
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`

func installLinux(exe, portable string) error {
	if os.Geteuid() != 0 {
		return errors.New("please run with sudo: sudo " + exe + " install")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd was not found – start the program directly instead")
	}
	fmt.Println("Installing WebTAK Server …")
	exec.Command("systemctl", "stop", "webtak-server").Run()
	if err := copyFile(exe, linuxBin, 0o755); err != nil {
		return err
	}
	if exec.Command("id", "webtak").Run() != nil {
		if err := run("useradd", "--system", "--home-dir", linuxData, "--shell", "/usr/sbin/nologin", "webtak"); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(linuxData, "state.json")); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(portable, "state.json")); err == nil {
			fmt.Println("Taking over the data of the portable version from", portable)
			copyDir(portable, linuxData)
		}
	}
	os.MkdirAll(linuxData, 0o700)
	run("chown", "-R", "webtak:webtak", linuxData)
	if err := os.WriteFile(linuxUnit, []byte(fmt.Sprintf(linuxUnitFile, linuxBin, linuxData)), 0o644); err != nil {
		return err
	}
	run("systemctl", "daemon-reload")
	if err := run("systemctl", "enable", "--now", "webtak-server"); err != nil {
		return err
	}
	// open the firewall if ufw is active
	if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
		for _, p := range strings.Split(allTCPPorts, ",") {
			exec.Command("ufw", "allow", p+"/tcp").Run()
		}
		for _, p := range strings.Split(videoPorts, ",") {
			exec.Command("ufw", "allow", p).Run()
		}
		fmt.Println("Firewall (ufw) opened for ports", allTCPPorts, "and video", videoPorts)
	}
	host := "<this-device-ip>"
	if ips := localIPs(); len(ips) > 0 {
		host = ips[0]
	}
	fmt.Println()
	fmt.Println("Done! WebTAK Server runs in the background and starts automatically.")
	fmt.Printf("Open in a browser:  https://%s:8443/\n", host)
	fmt.Println("(Your browser warns about the certificate the first time – choose \"Advanced\" → \"Continue\".)")
	fmt.Println("Status: sudo systemctl status webtak-server   Log: sudo journalctl -u webtak-server -f")
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
