# WebTAK Server

**Your own TAK server in one file.** Runs on Windows, Raspberry Pi, Linux and macOS – no database, no Docker,
no nginx, no command line knowledge needed. Works with **ATAK, iTAK and WinTAK** like OpenTAKServer (OTS), has the
same **video server (MediaMTX)** built in, and several servers can be **linked together** – WebTAK Servers among
each other (federation) and **with OpenTAKServer** (bridge) – so all their devices and video streams are shared.

```
 ATAK / iTAK / WinTAK ──▶ WebTAK Server A ◀══ federation ══▶ WebTAK Server B ◀── ATAK / iTAK / WinTAK
                               ▲                                   ║
                               ║ bridge                 federation ║
                               ▼                                   ║
                         OpenTAKServer                  WebTAK Server C
                    (its devices and video)
```

| | OpenTAKServer (see `OTS Anleitung Webseite.pdf`) | WebTAK Server |
|---|---|---|
| Install | Ubuntu/Pi OS, SSH, installer script, PostgreSQL, RabbitMQ, nginx, certbot … | download, double-click (Windows) or one command (Pi) |
| Runs on | Linux | Windows, Raspberry Pi (all models), Linux, macOS, Docker |
| Setup | default password `administrator`/`password`, edit nginx files | web wizard: set the admin password, done |
| Connect devices | QR code / data package | QR code (ATAK + iTAK) / data package (WinTAK) |
| Video server | MediaMTX (installed with OTS) | MediaMTX, started and configured automatically |
| Link servers | – (no server federation) | invite code, both directions, chains and rings – incl. video |
| Link with OTS | – | bridge: OTS devices and video appear here, ours there |

---

## Install

### Windows

1. Download **`WebTAK-Server-Windows-amd64.zip`** from [Releases](https://github.com/fredy060795/5040-WebTAK_Server/releases/latest) and unzip it.
   (Not the green *Code → Download ZIP* button – that is only the source code without the program. If you used it
   anyway, `install\windows\Install.bat` downloads the program from the releases by itself.)
2. **Try it:** double-click `webtak-server.exe`. Click *Allow* when Windows asks about network access.
   The browser opens the setup page by itself.
3. **Install for good:** double-click `Install.bat` (confirm the administrator question). The server then runs in
   the background, starts with Windows and the firewall is opened. Data of the test run is taken over.

Web interface on the server PC: <http://localhost:8080/> · from other devices: `https://<PC-IP>:8443/`

### Raspberry Pi / Linux

Open a terminal (or SSH) and paste:

```sh
curl -fsSL https://raw.githubusercontent.com/fredy060795/5040-WebTAK_Server/main/install/install.sh | sudo sh
```

That is all – the right program for the Pi model is downloaded, installed as a service that starts automatically,
and the firewall (ufw) is opened if active. Run the same command again to update.
Then open `https://<pi-ip>:8443/` in a browser (accept the certificate warning once: *Advanced → Continue*).

Works on every Raspberry Pi (Zero, 1–5, 32- and 64-bit OS), Ubuntu, Debian and other Linux systems with systemd.

### Docker

```sh
docker compose up -d
```

Then open `https://<host>:8443/` and set the server address under *Settings* (inside Docker the server cannot see the host's IP).

### Without installing (any system)

Download the file for your system from Releases and start it: `./webtak-server-linux-arm64`. Data is kept in a
folder `takdata` next to the program.

---

## First steps

1. **Setup wizard** – server name, admin password, optionally the address devices use (DNS name, DuckDNS,
   ZeroTier or Tailscale IP). Leave it empty for the local network address.
2. **Users** – create one user per person (password is generated if you leave it empty). Groups decide who sees whom.
3. **Connect devices** – choose the user → QR codes:
   - **ATAK:** *Settings → Network → Server Connections → ＋ → Scan QR* – everything is set up automatically
     (certificate enrollment, like with OTS).
   - **iTAK:** *Settings → Network → Servers → ＋ → Scan QR*, then log in with the user name and the shown password.
   - **WinTAK** (or ATAK without QR): *Download connection package* and drag the zip onto the map / import it.

Users can also log in to the web interface themselves and get the QR code for their own device under *My device*.

## Federation – linking servers

On server **A**: *Federation → Create invite code* → send the code to the admin of server **B**.
On server **B**: *Federation → Join with a code* → paste → *Link servers*. Done – the devices of A and B see each
other: positions, markers, drawings, chat (also direct messages) and data packages, in **both directions**.

- Only **B needs to reach A** (A's federation port 9000). B may sit behind a router or on a mobile connection – the one
  connection carries the data both ways. Reconnects happen automatically.
- **Chains and rings** work (A–B–C, or A–B–C–A): data is passed on with loop protection, nothing arrives twice.
  Can be switched off per link (*Edit → pass on data of further linked servers*).
- Per link you choose **which groups** are shared; a link can be switched off or removed on either side.
- Security: the invite contains a one-time token and the fingerprint of A's certificate authority. Both servers pin
  each other's certificates and agree on a secret for later reconnects; all traffic is TLS encrypted.
- The invite code contains all addresses of A. If B must use another address (DNS name, ZeroTier IP), enter it in
  the *Address* field when joining.
- **Video is shared too:** every stream of A appears on B as `fed-<server A>/<name>` (and the other way round) and
  shows up in ATAK's video list there. The video travels through the same federation connection, so it also works when
  only B can reach A – and it only flows while someone actually watches.

## Linking with OpenTAKServer (bridge)

OpenTAKServer has no server-to-server federation. WebTAK Server therefore connects to an OTS **like a device** and
relays in both directions: OTS users see the devices of this server *and of every federated WebTAK Server*, and
everyone here sees the OTS devices. Works with OpenTAKServer, TAK Server and FreeTAKServer.

1. In the OTS web interface create a user for the bridge, e.g. `webtak-bridge`, and add it to the groups that should be shared.
2. Here: *Federation → OpenTAKServer and other TAK servers → Connect* – enter the OTS address, user and password.
   The certificate is requested automatically on port 8446 (like ATAK's QR setup), then the bridge connects on 8089.
3. Optional video:
   - *Show the video streams of that server here* – OTS streams appear as `ots-<name>/<stream>` (pulled from the OTS
     MediaMTX with the bridge user, only while someone watches).
   - *Share our video streams with that server* – our streams are registered on the OTS (`wts-<name>/<stream>`); the
     OTS MediaMTX pulls them from us, so the OTS must be able to reach this server's RTSP port.

The bridge appears on the OTS as one contact (*"<server name> (WebTAK)"*, position under *Settings*). Group chat,
positions, markers and data package links pass both ways, and direct messages from here to an OTS user work.
Direct messages from an OTS user to a single user *here* do not arrive – OTS only delivers them to devices connected to
it directly. Use group chat (*All Chat Rooms*) across the bridge for that direction.

## Video (MediaMTX)

The video server starts with WebTAK Server – nothing to install (Windows: included in the download; Raspberry Pi /
Linux / macOS: downloaded automatically on the first start, or put `mediamtx` next to `webtak-server`).

- **Send video** with the login of any TAK user, to any name (it appears by itself):
  - DJI drone (DJI Fly / Pilot 2 → Livestream → RTMP), OBS, Larix: `rtmp://<server>:1935/drone-1?user=<user>&pass=<password>`
  - IP cameras, ffmpeg: `rtsp://<user>:<password>@<server>:8554/drone-1`
  - SRT (mobile networks): `srt://<server>:8890?streamid=publish:drone-1:<user>:<password>`
- **Watch:** ATAK / iTAK / WinTAK list every stream under *Video* (server feeds, same format as OTS); in the browser
  under *Video → ▶ Watch* (WebRTC) or with any player via RTSP/HLS.
- **Pull streams** from cameras on demand (*Video → Add a stream*, source `rtsp://…`), e.g. a fixed IP camera.
- Watching without a login is allowed by default (ATAK plays streams without a password); switch on
  *Watching needs a login* under *Settings* if needed. Sending always needs a login.
- The OTS video API (`/api/video_streams`, `/api/mediamtx/stream/add|update|delete`) is supported, so **WebTAK
  (port 5036)** registers its helmet/phone cameras here automatically, exactly as with OTS.

## Meshtastic radios (MQTT)

Like OpenTAKServer, the server has an **MQTT broker for Meshtastic** built in (port 8883, TLS). A radio with internet –
e.g. a fixed "HQ gateway" radio in the headquarters WLAN – logs in with a user of this server and passes everything
it hears on the mesh to the server. With the channel stored under Meshtastic (OTS API `/api/meshtastic/channel`,
WebTAK → Meshtastic) the server opens the encrypted packets with the channel key and every TAK device sees:

- **TAK users on the mesh** (ATAK Meshtastic plugin, TAKweb on a radio): position, team, role, battery, chat –
  also when their phone is closed, as long as the radio reports its GPS.
- **plain Meshtastic radios** as contacts `MESH-!xxxxxxxx` (name, position) and their messages in *All Chat Rooms*.
- Every event carries `<__mqtt gateway="!…" channel="…" hops="…"/>`: which radio uplinked it and over how many hops
  (TAKweb's *Network* view draws the exact way). A packet heard by several gateways is delivered once.
- Radios at different places that use the same server are **linked over the internet** (the broker passes their
  messages to each other, as on any Meshtastic MQTT server).

- **Back into the mesh (downlink):** in channels with downlink on, TAK group chat (also as plain text for the
  Meshtastic app), direct messages to TAK users heard on the mesh and the positions of the TAK users go to the radios –
  a position at most every 5 minutes, one packet every 3 seconds, so LoRa is not flooded.
- **Markers, drawings, routes, deletions** from the mesh (ATAK plugin / TAKweb, port 257, also the multi-packet
  "fountain" transfers) reach every TAK device; the sender gets the acknowledgement.
- Page **Meshtastic** in the web interface: gateways, connected radios, every radio heard with the way it came (gateway,
  hops), signal at the gateway (SNR/RSSI), battery and position. The same as JSON for tools: `/api/meshtastic/gateways`.

Radio settings (WebTAK's *Set up a radio* does this): MQTT on, address `<server>:8883`, TLS on, encryption on, root
topic `opentakserver` (any root works), the channel with *uplink* on. A channel created only by name gets its
Meshtastic link (`https://meshtastic.org/e/#…`) from the server, like in OTS.

## Ports

| Port | Use |
|---|---|
| 8089/tcp | TAK devices, SSL with client certificate (recommended) |
| 8088/tcp | TAK devices, unencrypted without login (can be switched off) |
| 8446/tcp | certificate enrollment (QR code setup) |
| 8443/tcp | web interface and Marti API (data packages) over HTTPS |
| 8080/tcp | Marti API over HTTP; web interface only from the server computer itself |
| 9000/tcp | federation |
| 8883/tcp | MQTT with TLS for Meshtastic radios (1883 without TLS only if switched on) |
| 8554/tcp | video RTSP (cameras send, ATAK plays) – 8000-8001/udp for RTSP over UDP |
| 1935/tcp | video RTMP (DJI drones, OBS) |
| 8890/udp | video SRT |
| 8888/tcp, 8889/tcp, 8189/udp | video in the browser (HLS, WebRTC) |

All ports can be changed with command line options (`webtak-server -help`). For access from the internet, forward
these ports in your router, or use **ZeroTier/Tailscale** (no port forwarding, as in the OTS guide).

## Compatibility

- **ATAK, iTAK, WinTAK** and other CoT clients: TCP and SSL streaming (CoT XML), certificate
  enrollment (`/Marti/api/tls/…`, QR `tak://com.atakmap.app/enroll`), data packages (`/Marti/sync/…`),
  contacts, groups, device profiles on enrollment and connection (`/Marti/api/tls/profile/enrollment`,
  `/Marti/api/device/profile/connection`), video lists (`/Marti/vcm`, `/Marti/api/video`, OTS format), Data Sync missions
  (`/Marti/api/missions/…`: create, subscribe, map items and files, CoT sent to a mission, change log and notices),
  ping/pong, latest positions for new devices.
- **Video through the web port** like OTS's nginx: `https://<server>:8443/hls/<stream>/index.m3u8?jwt=<token>` and `/webrtc/…`.
- **Groups like OTS / TAK Server:** IN = may send into the group, OUT = receives from it; `__ANON__` is the default group.
- **OTS web API** (`/api/login`, `/api/user/*`, `/api/users`, `/api/groups`, `/api/eud`, `/api/atak_qr_string`,
  `/api/truststore`, `/api/profiles`, `/api/missions`, `/api/video_streams`, `/api/mediamtx/stream/*`,
  `/api/meshtastic/channel`, `/api/meshtastic/generate_psk`, MQTT for Meshtastic): tools built for
  OpenTAKServer work unchanged. Tested with
  **WebTAK** (port 5036) – enter `https://<server>:8443` as OTS address with an admin login and allow the
  self-signed certificate.
- **Not included** (compared to OTS): video recording, Mumble, mission logs/keywords/external data and mission federation, TAK protocol
  version 1 (protobuf – devices automatically stay on XML). Federation is between WebTAK Servers (own protocol); other
  TAK servers are linked through the bridge (official TAK Server federation on port 9001 is not supported).

## Good to know

- **Backup:** copy the data folder (Windows: `C:\ProgramData\WebTAK Server`, Pi/Linux: `/var/lib/webtak-server`,
  portable: `takdata`). It contains users, certificates, links and data packages.
- **Forgot the admin password:** stop the server, then `webtak-server reset-password admin`
  (Pi: `sudo systemctl stop webtak-server && sudo -u webtak webtak-server reset-password -data /var/lib/webtak-server admin && sudo systemctl start webtak-server`).
- **Changing IP address:** the server certificate is renewed automatically when the computer gets a new address.
- **Own certificate** (e.g. Let's Encrypt for the web interface): *Settings → Own certificate*.
- **Logs:** web interface → *Log*; Pi: `sudo journalctl -u webtak-server -f`; file `server.log` in the data folder.
- Deleting or blocking a user revokes the certificates and disconnects the devices immediately.

## Build from source

```sh
go test ./...
go build -o webtak-server .                                    # this computer
GOOS=windows GOARCH=amd64 go build -o webtak-server.exe .       # Windows
GOOS=linux GOARCH=arm GOARM=6 go build -o webtak-server-pi .    # 32-bit Raspberry Pi
```

Releases are built by GitHub Actions: push a tag `v1.2.3` (or *Actions → Release → Run workflow*).

Code overview: `server.go` (ports, CoT connections) · `hub.go` (routing, groups) · `cot.go` (CoT parsing) ·
`marti.go` (device API, enrollment, data packages) · `federation.go` · `otsapi.go` (OTS-compatible API) ·
`admin.go` + `web/` (web interface) · `pki.go` (certificate authority) · `store.go` (data) · `service.go` (installers).
