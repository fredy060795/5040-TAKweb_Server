'use strict';
// WebTAK Server web interface – plain JavaScript, no build step.

const $ = sel => document.querySelector(sel);
const app = $('#app');
let me = null;
let timer = null;

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(method, path, body) {
  const opt = { method, headers: { 'X-WTS': '1' } };
  if (body instanceof FormData) opt.body = body;
  else if (body !== undefined) { opt.body = JSON.stringify(body); opt.headers['Content-Type'] = 'application/json'; }
  const r = await fetch('/admin/api/' + path, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { /* empty */ }
  if (r.status === 401 && path !== 'login' && me) { me = null; route(); }
  if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
  return data;
}

function toast(msg, ms = 3500) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, ms);
}
const fail = e => toast('⚠ ' + e.message, 6000);

function modal(html) {
  $('#modalBody').innerHTML = html;
  $('#modal').hidden = false;
}
function closeModal() { $('#modal').hidden = true; $('#modalBody').innerHTML = ''; }
$('#modalClose').onclick = closeModal;
$('#modal').addEventListener('click', e => { if (e.target.id === 'modal') closeModal(); });

function ago(t) {
  if (!t || t.startsWith('0001')) return '–';
  const s = Math.round((Date.now() - new Date(t)) / 1000);
  if (s < 60) return s + ' s ago';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return new Date(t).toLocaleDateString();
}
function bytes(n) { return n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n > 1024 ? Math.round(n / 1024) + ' KB' : n + ' B'; }
function copy(text) { navigator.clipboard.writeText(text).then(() => toast('Copied'), () => toast('Copy failed – select the text and copy it by hand')); }
window.copy = copy;

// ---------------------------------------------------------------- navigation

const PAGES = [
  ['dashboard', 'Dashboard'], ['connect', 'Connect devices'], ['users', 'Users'], ['groups', 'Groups'], ['devices', 'Devices'], ['meshtastic', 'Meshtastic'],
  ['map', 'Map'], ['federation', 'Federation'], ['packages', 'Data packages'], ['video', 'Video'], ['settings', 'Settings'], ['log', 'Log'],
];

async function route() {
  clearInterval(timer);
  let st;
  try { st = await api('GET', 'state'); } catch (e) { app.innerHTML = `<p class="err center">Server not reachable: ${esc(e.message)}</p>`; return; }
  $('#srvName').textContent = st.serverName || 'WebTAK Server';
  document.title = st.serverName || 'WebTAK Server';
  if (!st.setupDone) { $('#top').hidden = true; return pageSetup(st); }
  if (!st.user) { $('#top').hidden = true; me = null; return pageLogin(); }
  me = st;
  $('#top').hidden = false;
  $('#whoName').textContent = st.user;
  const page = (location.hash || '#').slice(1) || (st.admin ? 'dashboard' : 'mydevice');
  const pages = st.admin ? PAGES : [['mydevice', 'My device']];
  $('#nav').innerHTML = pages.map(([id, name]) => `<a href="#${id}" class="${id === page ? 'active' : ''}">${name}</a>`).join('');
  const fn = { dashboard: pageDashboard, connect: pageConnect, users: pageUsers, groups: pageGroups, devices: pageDevices, meshtastic: pageMeshtastic, map: pageMap,
    federation: pageFederation, packages: pagePackages, video: pageVideo, settings: pageSettings, log: pageLog, mydevice: pageMyDevice }[page];
  if (!fn || (!st.admin && page !== 'mydevice')) { location.hash = st.admin ? '#dashboard' : '#mydevice'; return; }
  try { await fn(); } catch (e) { app.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
}
window.addEventListener('hashchange', route);
$('#logoutBtn').onclick = async () => { await api('POST', 'logout').catch(() => {}); me = null; location.hash = ''; route(); };

// ---------------------------------------------------------------- setup & login

function pageSetup(st) {
  const ips = (st.ips || []).join(', ') || 'none found';
  app.innerHTML = `<div class="narrow card">
    <h1>Welcome to WebTAK Server</h1>
    <p class="muted">Three quick settings and your TAK server is ready.</p>
    <form id="f">
      <label>Name of this server (shown in ATAK / iTAK)</label>
      <input type="text" name="serverName" value="${esc(st.hostname ? 'TAK ' + st.hostname : 'WebTAK Server')}" required>
      <label>Administrator user name</label>
      <input type="text" name="username" value="admin" required autocomplete="username">
      <label>Administrator password (at least 8 characters)</label>
      <input type="password" name="password" required minlength="8" autocomplete="new-password">
      <label>Repeat password</label>
      <input type="password" name="password2" required minlength="8" autocomplete="new-password">
      <label>Address of this server for the devices (optional)</label>
      <input type="text" name="publicHost" placeholder="automatic – e.g. tak.example.com or 10.147.17.5">
      <p class="small muted">Leave empty to use the local network address (found: ${esc(ips)}). Enter a DNS name
      (DuckDNS, own domain) or a ZeroTier/Tailscale address if devices connect from outside. You can change it later.</p>
      <p><button>Finish setup</button> <span id="msg" class="err"></span></p>
    </form></div>`;
  $('#f').onsubmit = async e => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    if (f.password !== f.password2) { $('#msg').textContent = 'The passwords do not match.'; return; }
    try { await api('POST', 'setup', f); location.hash = '#connect'; route(); } catch (err) { $('#msg').textContent = err.message; }
  };
}

function pageLogin() {
  app.innerHTML = `<div class="narrow card">
    <h1>Log in</h1>
    <p class="muted">Administrators manage the server. Users can get the setup for their device here.</p>
    <form id="f">
      <label>User name</label><input type="text" name="username" required autocomplete="username" autofocus>
      <label>Password</label><input type="password" name="password" required autocomplete="current-password">
      <p><button>Log in</button> <span id="msg" class="err"></span></p>
    </form>
    <p class="small muted">Forgot the admin password? On the server run <code>webtak-server reset-password admin</code> (stop the server first).</p></div>`;
  $('#f').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'login', Object.fromEntries(new FormData(e.target))); route(); } catch (err) { $('#msg').textContent = err.message; }
  };
}

// ---------------------------------------------------------------- dashboard

async function pageDashboard() {
  const d = await api('GET', 'dashboard');
  const p = d.ports;
  const portRow = (name, port, what) => port > 0 ? `<tr><td>${name}</td><td><code>${port}</code></td><td class="muted">${what}</td></tr>` : '';
  app.innerHTML = `
    <div class="row spread"><div><h1>${esc(d.serverName)}</h1><p class="muted">WebTAK Server ${esc(d.version)} · ${esc(d.os)} · running since ${esc(new Date(d.started).toLocaleString())}</p></div>
    <a class="btn" href="#connect">+ Connect a device</a></div>
    <div class="grid">
      <div class="stat"><b>${d.clients}</b><span>devices online</span></div>
      <div class="stat"><b>${d.contacts}</b><span>contacts on the map</span></div>
      <div class="stat"><b>${d.users}</b><span>users</span></div>
      <div class="stat"><b>${d.fedConnected} / ${d.fedLinks}</b><span>federated servers online</span></div>
      <div class="stat"><b>${d.packages}</b><span>data packages</span></div>
    </div>
    <div class="card"><h2>Getting started</h2><ol class="steps">
      <li><a href="#users">Create a user</a> for every person (or one per team).</li>
      <li><a href="#connect">Connect the device</a>: scan the QR code with ATAK or iTAK – or download the connection package for WinTAK.</li>
      <li>Done – everyone sees everyone. To link with other servers use <a href="#federation">Federation</a>.</li>
    </ol></div>
    <div class="card"><h2>Addresses</h2>
      <p>Devices connect to <code>${esc(d.publicHost)}</code>${d.configuredHost ? '' : ' <span class="muted small">(automatic – set a fixed address under <a href="#settings">Settings</a> if devices connect from outside)</span>'}</p>
      <p class="small muted">Network addresses of this computer: ${(d.ips || []).map(i => `<code>${esc(i)}</code>`).join(' ') || 'none'} · name <code>${esc(d.hostname)}</code></p>
      <div class="table-wrap"><table><tr><th>Purpose</th><th>Port</th><th>Notes</th></tr>
      ${portRow('TAK devices (SSL, recommended)', p.SSL, 'ATAK / iTAK / WinTAK with certificate')}
      ${portRow('TAK devices (TCP, unencrypted)', p.TCP, 'no login – only for trusted networks')}
      ${portRow('Certificate enrollment', p.Enroll, 'QR code setup of ATAK / iTAK')}
      ${portRow('HTTPS: web interface + data packages', p.HTTPS, 'https://' + esc(d.publicHost) + ':' + p.HTTPS)}
      ${portRow('HTTP: data packages', p.HTTP, 'web interface only from this computer')}
      ${portRow('Federation', p.Fed, 'links to other servers')}
      ${portRow('Video RTSP', p.RTSP, 'cameras send / ATAK plays video')}
      ${portRow('Video RTMP', p.RTMP, 'DJI drones, OBS, Larix')}
      ${portRow('Video SRT (UDP)', p.SRT, 'OBS, Larix over mobile networks')}
      ${portRow('Video HLS / WebRTC', p.HLS, 'watch in the browser (WebRTC ' + p.WebRTC + ')')}
      </table></div>
      <p class="hint small">From outside your network (internet): forward these TCP ports in your router to this computer, or use ZeroTier / Tailscale (no port forwarding needed).</p>
    </div>
    <div class="card"><h2>Message to all devices</h2>
      <form id="chat" class="row"><input type="text" name="text" placeholder="Text sent as chat to All Chat Rooms" style="flex:1"><button>Send</button></form>
    </div>`;
  $('#chat').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'chat', { text: e.target.text.value }); e.target.text.value = ''; toast('Sent'); } catch (err) { fail(err); }
  };
}

// ---------------------------------------------------------------- connect devices

async function hostOptions() {
  const d = await api('GET', 'dashboard');
  const list = [];
  if (d.configuredHost) list.push(d.configuredHost);
  for (const ip of d.ips || []) if (!list.includes(ip)) list.push(ip);
  if (location.hostname && !['localhost', '127.0.0.1'].includes(location.hostname) && !list.includes(location.hostname)) list.push(location.hostname);
  return list;
}

async function pageConnect() {
  const [users, hosts] = await Promise.all([api('GET', 'users'), hostOptions()]);
  app.innerHTML = `<h1>Connect devices</h1>
    <p class="muted">Pick the user, then scan the QR code on the phone/tablet. Every device gets its own certificate automatically.</p>
    <div class="card">
      <div class="row">
        <div style="flex:1;min-width:200px"><label>User</label><select id="u">${users.map(u => `<option>${esc(u.username)}</option>`).join('')}</select></div>
        <div style="flex:1;min-width:200px"><label>Server address for the device</label><select id="h">${hosts.map(h => `<option>${esc(h)}</option>`).join('')}</select></div>
        <div style="align-self:flex-end"><button id="go">Show QR codes</button></div>
      </div>
      <p class="small muted">No user yet? <a href="#users">Create one</a>. The address must be reachable from the device (same Wi-Fi, ZeroTier/Tailscale, or internet with port forwarding).</p>
    </div>
    <div id="out"></div>`;
  $('#go').onclick = () => showConnect($('#u').value, $('#h').value, $('#out'));
}

async function showConnect(user, host, target) {
  if (!user) { toast('Please create a user first'); return; }
  const q = host ? '?host=' + encodeURIComponent(host) : '';
  try {
    const r = await api('POST', (user === me.user && !me.admin ? 'me/connect' : 'users/' + encodeURIComponent(user) + '/enroll') + q, { maxUses: 3, hours: 72 });
    const pkg = (user === me.user && !me.admin ? 'me/package' : 'users/' + encodeURIComponent(user) + '/package') + q;
    target.innerHTML = `<div class="card">
      <div class="qr-grid">
        <div class="qr"><h2>ATAK (Android)</h2><img src="${r.atakQR}" alt="ATAK QR code">
          <p class="small">ATAK → ☰ → <b>Settings → Network → Server Connections → ＋ → Scan QR</b>. Everything is set up automatically.</p></div>
        <div class="qr"><h2>iTAK (iPhone / iPad)</h2><img src="${r.itakQR}" alt="iTAK QR code">
          <p class="small">iTAK → <b>Settings → Network → Servers → ＋ → Scan QR</b>, then log in with<br>
          user <code>${esc(r.username)}</code> and password <code>${esc(r.token)}</code></p></div>
      </div>
      <p class="small muted center">The code works ${r.maxUses}× and is valid until ${esc(new Date(r.expires).toLocaleString())}. Server ${esc(r.host)}, SSL port ${r.sslPort}, enrollment port ${r.enrollPort}.</p>
      <hr style="border:0;border-top:1px solid var(--line)">
      <h2>WinTAK, or ATAK without QR</h2>
      <p class="small">Download the connection package and import it: <b>WinTAK</b> – drag the .zip onto the map (or Import Manager);
      <b>ATAK</b> – copy it to the device, then ☰ → Import → Local SD. Certificate password: as set under Settings (default <code>atakatak</code>).</p>
      <p><a class="btn ghost" href="/admin/api/${pkg}">⬇ Download connection package (.zip)</a></p>
    </div>`;
  } catch (e) { fail(e); }
}

async function pageMyDevice() {
  app.innerHTML = `<h1>My device</h1><p class="muted">Set up ATAK, iTAK or WinTAK for <b>${esc(me.user)}</b>.</p>
    <div id="out"></div>
    <div class="card"><h2>Change password</h2><form id="pw">
      <label>Current password</label><input type="password" name="old" required>
      <label>New password (at least 8 characters)</label><input type="password" name="new" required minlength="8">
      <p><button>Change</button></p></form></div>`;
  showConnect(me.user, '', $('#out'));
  $('#pw').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'me/password', Object.fromEntries(new FormData(e.target))); e.target.reset(); toast('Password changed'); } catch (err) { fail(err); }
  };
}

// ---------------------------------------------------------------- users

async function pageUsers() {
  const [users, groups] = await Promise.all([api('GET', 'users'), api('GET', 'groups')]);
  app.innerHTML = `<div class="row spread"><h1>Users</h1><button id="add">+ New user</button></div>
    <p class="muted">Every person logs in with their own user. Deleting or blocking a user disconnects their devices immediately.</p>
    <div class="card table-wrap"><table>
      <tr><th>User</th><th>Groups (in / out)</th><th>Devices</th><th>Status</th><th></th></tr>
      ${users.map(u => {
        const ins = u.groups.filter(g => g.direction === 'IN').map(g => g.group);
        const outs = u.groups.filter(g => g.direction === 'OUT').map(g => g.group);
        const same = ins.length === outs.length && ins.every(g => outs.includes(g));
        const gtxt = same ? ins.map(g => `<span class="chip">${esc(g)}</span>`).join('') : `in: ${ins.map(g => `<span class="chip">${esc(g)}</span>`).join('')}<br>out: ${outs.map(g => `<span class="chip">${esc(g)}</span>`).join('')}`;
        return `<tr data-u="${esc(u.username)}">
        <td><b>${esc(u.username)}</b>${u.admin ? ' <span class="chip">admin</span>' : ''}<div class="small muted">created ${ago(u.created)}</div></td>
        <td>${gtxt || '<span class="muted">none</span>'}</td>
        <td>${u.online ? `<span class="dot ok"></span>${u.online} online` : ''} ${(u.devices || []).map(d => `<span class="chip">${esc(d)}</span>`).join('')}<div class="small muted">${u.certs} certificate(s)</div></td>
        <td>${u.active ? '<span class="dot ok"></span>active' : '<span class="dot bad"></span>blocked'}</td>
        <td class="row"><button class="small" data-a="connect">QR / package</button><button class="small ghost" data-a="edit">Edit</button></td></tr>`;
      }).join('')}
    </table></div>`;
  $('#add').onclick = () => editUser(null, groups);
  app.querySelectorAll('[data-a]').forEach(b => b.onclick = () => {
    const name = b.closest('tr').dataset.u;
    const u = users.find(x => x.username === name);
    if (b.dataset.a === 'connect') { location.hash = '#connect'; setTimeout(() => { $('#u').value = name; $('#go').click(); }, 300); }
    else editUser(u, groups);
  });
}

function groupPicker(groups, selected) {
  return groups.map(g => `<label class="check"><input type="checkbox" name="g" value="${esc(g.name)}" ${selected.includes(g.name) ? 'checked' : ''}> ${esc(g.name)} <span class="muted small">${esc(g.description || '')}</span></label>`).join('');
}

function editUser(u, groups) {
  const isNew = !u;
  const sel = isNew ? ['__ANON__'] : u.groups.filter(g => g.direction === 'OUT').map(g => g.group);
  modal(`<h2>${isNew ? 'New user' : 'User ' + esc(u.username)}</h2><form id="uf">
    ${isNew ? `<label>User name (letters, digits, _ - .)</label><input type="text" name="username" required>
    <label>Password (empty = generate one)</label><input type="text" name="password" placeholder="automatic">` : ''}
    <label>Groups – the user sees and is seen by members of these groups</label>${groupPicker(groups, sel)}
    <label class="check"><input type="checkbox" name="admin" ${u && u.admin ? 'checked' : ''}> Administrator (may manage this server)</label>
    ${isNew ? '' : `<label class="check"><input type="checkbox" name="active" ${u.active ? 'checked' : ''}> Active (unchecked = blocked, devices are disconnected)</label>`}
    <p class="row"><button>${isNew ? 'Create' : 'Save'}</button>
    ${isNew ? '' : '<button type="button" class="ghost" id="pwreset">New password</button><button type="button" class="danger" id="del">Delete user</button>'}</p>
    <p id="res"></p></form>`);
  const f = $('#uf');
  f.onsubmit = async e => {
    e.preventDefault();
    const gs = [...f.querySelectorAll('[name=g]:checked')].map(x => x.value);
    try {
      if (isNew) {
        const r = await api('POST', 'users', { username: f.username.value.trim(), password: f.password.value, admin: f.admin.checked, groups: gs });
        $('#res').innerHTML = `<div class="hint">User created. Password: <code>${esc(r.password)}</code> <button type="button" class="small ghost" id="cpw">Copy</button><br>
          Next: <a href="#connect" onclick="document.getElementById('modal').hidden=true">connect the device</a>.</div>`;
        f.querySelector('button').disabled = true;
        $('#cpw').onclick = () => copy(r.password);
      } else {
        const memberships = gs.flatMap(g => [{ group: g, direction: 'IN' }, { group: g, direction: 'OUT' }]);
        await api('PUT', 'users/' + encodeURIComponent(u.username), { admin: f.admin.checked, active: f.active.checked, groups: memberships });
        closeModal(); toast('Saved');
      }
      if (!isNew) route();
      else setTimeout(route, 50);
    } catch (err) { $('#res').innerHTML = `<span class="err">${esc(err.message)}</span>`; }
  };
  if (!isNew) {
    $('#pwreset').onclick = async () => {
      const pw = prompt('New password (empty = generate one):', '');
      if (pw === null) return;
      try { const r = await api('PUT', 'users/' + encodeURIComponent(u.username), { password: pw }); $('#res').innerHTML = `<div class="hint">New password: <code>${esc(r.password)}</code></div>`; } catch (err) { fail(err); }
    };
    $('#del').onclick = async () => {
      if (!confirm(`Delete ${u.username}? Their certificates are revoked and their devices disconnected.`)) return;
      try { await api('DELETE', 'users/' + encodeURIComponent(u.username)); closeModal(); route(); } catch (err) { fail(err); }
    };
  }
}

// ---------------------------------------------------------------- groups

async function pageGroups() {
  const groups = await api('GET', 'groups');
  app.innerHTML = `<h1>Groups</h1>
    <p class="muted">Groups decide who sees whom (like channels in TAK Server / OpenTAKServer). Users in the same group see each other.
    <code>__ANON__</code> is the default group – also for devices on the unencrypted TCP port.</p>
    <div class="card"><form id="gf" class="row"><input type="text" name="name" placeholder="Group name, e.g. Team-Red" style="flex:1" required>
      <input type="text" name="description" placeholder="Description (optional)" style="flex:2"><button>Create group</button></form></div>
    <div class="card table-wrap"><table><tr><th>Group</th><th>Description</th><th>Members</th><th></th></tr>
    ${groups.map(g => `<tr><td><b>${esc(g.name)}</b></td><td>${esc(g.description)}</td><td>${g.members}</td>
      <td>${g.name === '__ANON__' ? '' : `<button class="small danger" data-del="${esc(g.name)}">Delete</button>`}</td></tr>`).join('')}
    </table></div>`;
  $('#gf').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'groups', Object.fromEntries(new FormData(e.target))); route(); } catch (err) { fail(err); }
  };
  app.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
    if (!confirm('Delete group ' + b.dataset.del + '?')) return;
    try { await api('DELETE', 'groups/' + encodeURIComponent(b.dataset.del)); route(); } catch (err) { fail(err); }
  });
}

// ---------------------------------------------------------------- devices

async function pageDevices() {
  const render = async () => {
    const [clients, euds] = await Promise.all([api('GET', 'clients'), api('GET', 'euds')]);
    app.innerHTML = `<h1>Devices</h1>
      <div class="card table-wrap"><h2>Connected now (${clients.length})</h2><table>
      <tr><th>Callsign</th><th>User</th><th>Connection</th><th>Groups</th><th>Messages in/out</th><th></th></tr>
      ${clients.map(c => `<tr><td><b>${esc(c.callsign || '…')}</b><div class="small muted">${esc(c.uid)}</div></td><td>${esc(c.username || '(anonymous)')}</td>
        <td>${c.tls ? 'SSL' : 'TCP'} · ${esc(c.remote)}<div class="small muted">since ${ago(c.connected)}</div></td>
        <td>${(c.out || []).map(g => `<span class="chip">${esc(g)}</span>`).join('')}</td><td>${c.rx} / ${c.tx}</td>
        <td><button class="small danger" data-kick="${c.id}">Disconnect</button></td></tr>`).join('') || '<tr><td colspan="6" class="muted">No device connected.</td></tr>'}
      </table></div>
      <div class="card table-wrap"><h2>Known devices (${euds.length})</h2><table>
      <tr><th>Callsign</th><th>User</th><th>Device</th><th>Team / role</th><th>Last seen</th><th></th></tr>
      ${euds.map(e => `<tr><td><b>${esc(e.callsign)}</b><div class="small muted">${esc(e.uid)}</div></td><td>${esc(e.username)}</td>
        <td>${esc(e.platform)} ${esc(e.version)}<div class="small muted">${esc(e.device)}</div></td><td>${esc(e.team)} ${esc(e.role)}</td>
        <td><span class="dot ${e.lastStatus === 'Connected' ? 'ok' : ''}"></span>${ago(e.lastEventTime)}</td>
        <td><button class="small ghost" data-forget="${esc(e.uid)}">Forget</button></td></tr>`).join('')}
      </table></div>`;
    app.querySelectorAll('[data-kick]').forEach(b => b.onclick = async () => { await api('DELETE', 'clients/' + b.dataset.kick).catch(fail); setTimeout(render, 300); });
    app.querySelectorAll('[data-forget]').forEach(b => b.onclick = async () => { await api('DELETE', 'euds/' + encodeURIComponent(b.dataset.forget)).catch(fail); render(); });
  };
  await render();
  timer = setInterval(() => { if (!document.hidden && $('#modal').hidden) render().catch(() => {}); }, 10000);
}

// ---------------------------------------------------------------- Meshtastic (MQTT)

async function pageMeshtastic() {
  const render = async () => {
    const d = await api('GET', 'meshtastic');
    const nodes = (d.nodes || []).sort((a, b) => new Date(b.heard) - new Date(a.heard));
    const gws = (d.gateways || []).sort((a, b) => new Date(b.last) - new Date(a.last));
    const chans = d.channels || [];
    const name = id => { const n = nodes.find(x => x.id === id); return n && (n.longName || n.shortName) ? `${esc(n.longName || n.shortName)} <span class="small muted">${esc(id)}</span>` : esc(id); };
    const hops = h => (h == null || h < 0 ? '?' : h === 0 ? 'direct' : h + ' hop' + (h === 1 ? '' : 's'));
    const fresh = t => (Date.now() - new Date(t)) < 15 * 60000;
    app.innerHTML = `<h1>Meshtastic</h1>
      <div class="card"><p class="small">Radios with internet log in to the MQTT broker of this server
        (${d.port > 0 ? `port <code>${d.port}</code> with TLS` : '<b>off</b> – switch it on under Settings'}${d.plainPort > 0 ? `, <code>${d.plainPort}</code> without TLS` : ''})
        with a user of this server and pass on what they hear. With the channel key the server opens the packets: positions,
        chat, markers and drawings reach every TAK device. TAK chat and positions go back into channels with downlink on
        (as radio <code>${esc(d.serverNode)}</code>; sent ${d.downlinkSent}, waiting ${d.downlinkPending}).</p>
        <p class="small muted">Radio settings: MQTT on, address <code>&lt;server&gt;:${d.port > 0 ? d.port : 8883}</code>, TLS on, encryption on,
        root topic <code>opentakserver</code>, the channel with uplink (and downlink) on. WebTAK's "Set up a radio" does all of it.</p>
        <p>${chans.map(c => `<span class="chip">${esc(c.name)}${c.downlink ? ' ⇅' : ' ↑'}</span>`).join(' ') || '<span class="err">No channel yet – add one in WebTAK (Meshtastic) or over the OTS API. Without the key nothing can be read.</span>'}</p></div>
      <div class="card table-wrap"><h2>Gateways (${gws.length})</h2><table>
      <tr><th>Radio</th><th>Channel</th><th>Packets</th><th>User</th><th>Last</th></tr>
      ${gws.map(g => `<tr><td><span class="dot ${fresh(g.last) ? 'ok' : ''}"></span>${name(g.gateway)}</td><td>${esc(g.channel)}</td><td>${g.packets}</td>
        <td>${esc(g.username)}</td><td>${ago(g.last)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted">No radio has sent anything yet.</td></tr>'}
      </table></div>
      <div class="card table-wrap"><h2>Connected now (${(d.clients || []).length})</h2><table>
      <tr><th>Client</th><th>User</th><th>From</th></tr>
      ${(d.clients || []).map(c => `<tr><td>${name(c.clientId)}</td><td>${esc(c.username)}</td><td class="small muted">${esc(c.remote)}</td></tr>`).join('') || '<tr><td colspan="3" class="muted">None.</td></tr>'}
      </table></div>
      <div class="card table-wrap"><h2>Radios heard (${nodes.length})</h2><table>
      <tr><th>Radio</th><th>TAK user</th><th>Via</th><th>Signal at the gateway</th><th>Battery</th><th>Position</th><th>Last heard</th></tr>
      ${nodes.map(n => `<tr><td>${name(n.id)}</td><td class="small">${esc(n.takUid || '')}</td><td class="small">${name(n.gateway)} · ${hops(n.hops)}</td>
        <td class="small">${n.gateway === n.id ? '<span class="muted">(the gateway itself)</span>' : n.hops === 0 ? `SNR ${(+n.snr).toFixed(1)} dB · RSSI ${n.rssi} dBm` : '<span class="muted">(relayed)</span>'}</td>
        <td>${n.battery != null ? (n.battery > 100 ? 'external' : n.battery + ' %') : ''}</td>
        <td class="small">${n.lat != null ? `${(+n.lat).toFixed(4)}, ${(+n.lon).toFixed(4)}` : '<span class="muted">none</span>'}</td>
        <td><span class="dot ${fresh(n.heard) ? 'ok' : ''}"></span>${ago(n.heard)}</td></tr>`).join('') || '<tr><td colspan="7" class="muted">Nothing heard yet.</td></tr>'}
      </table></div>`;
  };
  await render();
  timer = setInterval(() => { if (!document.hidden) render().catch(() => {}); }, 10000);
}

// ---------------------------------------------------------------- map

let mapObj = null;
async function pageMap() {
  app.innerHTML = `<div class="row spread"><h1>Map</h1><span class="small muted" id="mapInfo"></span></div><div id="map"></div>
    <p class="small muted">Positions of all devices this server knows – local and from federated servers. Map tiles need internet access (OpenStreetMap).</p>`;
  if (!window.L) { $('#map').innerHTML = '<p class="muted center">Map library not loaded.</p>'; return; }
  mapObj = L.map('map').setView([50, 10], 4);
  L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '© OpenStreetMap' }).addTo(mapObj);
  const layer = L.layerGroup().addTo(mapObj);
  let fitted = false;
  const colors = { Cyan: '#00bcd4', White: '#ddd', Yellow: '#fdd835', Orange: '#fb8c00', Magenta: '#d81b60', Red: '#e53935', Maroon: '#800000',
    Purple: '#8e24aa', 'Dark Blue': '#1a237e', Blue: '#1e88e5', Teal: '#00897b', Green: '#43a047', 'Dark Green': '#1b5e20', Brown: '#6d4c41' };
  const draw = async () => {
    const list = await api('GET', 'contacts');
    layer.clearLayers();
    const pts = [];
    for (const c of list) {
      if (!c.lat && !c.lon) continue;
      pts.push([c.lat, c.lon]);
      L.circleMarker([c.lat, c.lon], { radius: 8, weight: 2, color: '#111', fillColor: colors[c.team] || (c.type.startsWith('a-h') ? '#e53935' : '#1e88e5'), fillOpacity: c.stale ? 0.35 : 0.9 })
        .bindTooltip(`<b>${esc(c.callsign || c.uid)}</b><br>${esc(c.team)} ${esc(c.role)}<br>${esc(c.origin)} · ${ago(c.time)}`).addTo(layer);
    }
    $('#mapInfo').textContent = pts.length + ' position(s)';
    if (!fitted && pts.length) { mapObj.fitBounds(pts, { maxZoom: 14, padding: [30, 30] }); fitted = true; }
  };
  await draw();
  timer = setInterval(() => { if (!document.hidden) draw().catch(() => {}); }, 5000);
}

// ---------------------------------------------------------------- federation

async function pageFederation() {
  const [f, groups, bridges] = await Promise.all([api('GET', 'federation'), api('GET', 'groups'), api('GET', 'bridges')]);
  app.innerHTML = `<h1>Federation</h1>
    <p class="muted">Link this server with other WebTAK Servers. Devices on all linked servers see each other – positions, markers, chat and data packages, in both directions.</p>
    ${f.enabled ? '' : '<p class="hint">Incoming federation connections are switched off under Settings.</p>'}
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
      <div class="card"><h2>1 · Invite another server</h2>
        <p class="small">Create a code here and paste it on the other server. The other server must be able to reach this one on port <code>${f.port}</code>
        (same network, ZeroTier/Tailscale, or port forwarding). The code works once and for 7 days.</p>
        <form id="inv" class="row"><input type="text" name="label" placeholder="Note, e.g. Unit B (optional)" style="flex:1"><button>Create invite code</button></form>
        <div id="invOut"></div></div>
      <div class="card"><h2>2 · Join with a code</h2>
        <p class="small">Paste the invite code you got from the other server's administrator.</p>
        <form id="join"><textarea name="code" placeholder="WTS1-…" required></textarea>
        <label>Address of the other server (optional – only if the code's addresses do not work, e.g. tak.example.com)</label>
        <input type="text" name="address" placeholder="automatic">
        <p><button>Link servers</button> <span id="joinMsg"></span></p></form></div>
    </div>
    <div class="card table-wrap"><h2>Linked servers</h2><table>
      <tr><th>Server</th><th>Status</th><th>Shares</th><th>Traffic</th><th></th></tr>
      ${f.links.map(l => `<tr data-id="${esc(l.id)}">
        <td><b>${esc(l.peerName)}</b><div class="small muted">${l.outgoing ? 'this server connects to ' + esc((l.addresses || [])[0] || '') : 'connects to this server'}</div></td>
        <td>${!l.enabled ? '<span class="dot"></span>switched off' : l.connected ? `<span class="dot ok"></span>connected ${ago(l.since)}<div class="small muted">${esc(l.remote)}</div>`
          : `<span class="dot bad"></span>not connected${l.lastSeen && !l.lastSeen.startsWith('0001') ? ' · last ' + ago(l.lastSeen) : ''}<div class="small err">${esc(l.error || (l.outgoing ? 'retrying …' : 'waiting for the other server'))}</div>`}</td>
        <td class="small">${(l.groups && l.groups.length) ? l.groups.map(g => `<span class="chip">${esc(g)}</span>`).join('') : 'all groups'}${l.transit ? '<div class="muted">+ data of further linked servers</div>' : ''}</td>
        <td class="small">${l.connected ? `${l.rx} in / ${l.tx} out` : ''}</td>
        <td class="row"><button class="small ghost" data-a="edit">Edit</button><button class="small ghost" data-a="toggle">${l.enabled ? 'Switch off' : 'Switch on'}</button><button class="small danger" data-a="del">Remove</button></td></tr>`).join('')
        || '<tr><td colspan="5" class="muted">No linked servers yet.</td></tr>'}
    </table></div>
    ${f.invites && f.invites.length ? `<div class="card table-wrap"><h2>Open invites</h2><table><tr><th>Note</th><th>Created</th><th>Valid until</th><th></th></tr>
      ${f.invites.map(i => `<tr><td>${esc(i.label || '–')}</td><td>${ago(i.created)}</td><td>${esc(new Date(i.expires).toLocaleString())}</td>
        <td><button class="small danger" data-inv="${esc(i.token)}">Cancel</button></td></tr>`).join('')}</table></div>` : ''}
    <div class="card table-wrap"><h2>OpenTAKServer and other TAK servers</h2>
      <p class="small">OpenTAKServer has no server federation – this server connects to it like a device instead (a "bridge") and relays in both
      directions: everyone on the OTS sees the devices here and on all linked WebTAK Servers, and the other way round. Works with OpenTAKServer,
      TAK Server and FreeTAKServer.</p>
      <table><tr><th>TAK server</th><th>Status</th><th>Video</th><th>Traffic</th><th></th></tr>
      ${bridges.map(b => `<tr data-bid="${esc(b.id)}"><td><b>${esc(b.name)}</b><div class="small muted">${esc(b.host)}:${b.streamPort} ${b.tls ? 'SSL' : 'TCP'} · user ${esc(b.username || '–')}</div>
        <div class="small muted">appears there as <i>${esc(b.callsign)}</i></div></td>
        <td>${!b.enabled ? '<span class="dot"></span>switched off' : b.connected ? `<span class="dot ok"></span>connected ${ago(b.since)}` : '<span class="dot bad"></span>not connected'}
          ${b.error ? `<div class="small err">${esc(b.error)}</div>` : ''}</td>
        <td class="small">${b.importVideo ? 'shows its video here' : ''}${b.importVideo && b.exportVideo ? '<br>' : ''}${b.exportVideo ? 'shares our video there' : ''}${!b.importVideo && !b.exportVideo ? '–' : ''}</td>
        <td class="small">${b.connected ? `${b.rx} in / ${b.tx} out` : ''}</td>
        <td class="row"><button class="small ghost" data-b="edit">Edit</button><button class="small ghost" data-b="toggle">${b.enabled ? 'Switch off' : 'Switch on'}</button><button class="small danger" data-b="del">Remove</button></td></tr>`).join('')
        || '<tr><td colspan="5" class="muted">No TAK server connected.</td></tr>'}</table>
      <details style="margin-top:12px"><summary><b>+ Connect an OpenTAKServer / TAK server</b></summary>
      <form id="bf">
        <p class="small">1. On the OTS create a user for this bridge (e.g. <code>webtak-bridge</code>) and put it into the groups that should be shared.<br>
        2. Enter its address and login here. The certificate is requested automatically (like ATAK's QR setup).</p>
        <div class="row"><div style="flex:2;min-width:200px"><label>Address of the TAK server</label><input type="text" name="host" required placeholder="ots.example.com or 192.168.1.20"></div>
        <div style="flex:1;min-width:140px"><label>Name (optional)</label><input type="text" name="name" placeholder="e.g. OTS Unit A"></div></div>
        <div class="row"><div style="flex:1;min-width:160px"><label>User name on that server</label><input type="text" name="username"></div>
        <div style="flex:1;min-width:160px"><label>Password</label><input type="password" name="password" autocomplete="new-password"></div></div>
        <label class="check"><input type="checkbox" name="tls" checked> SSL (port 8089 with certificate – recommended). Unchecked: unencrypted TCP port 8088 without login.</label>
        <label class="check"><input type="checkbox" name="importVideo" checked> Show the video streams of that server here</label>
        <label class="check"><input type="checkbox" name="exportVideo"> Share our video streams with that server (OpenTAKServer; it must be able to reach this server)</label>
        <details><summary class="small">Ports (only if not the defaults)</summary><div class="row">
          <div><label>Streaming</label><input type="number" name="streamPort" placeholder="8089 / 8088"></div>
          <div><label>Enrollment</label><input type="number" name="enrollPort" placeholder="8446"></div>
          <div><label>Marti API</label><input type="number" name="apiPort" placeholder="8443"></div>
          <div><label>Web / OTS API</label><input type="number" name="webPort" placeholder="443"></div>
          <div><label>RTSP</label><input type="number" name="rtspPort" placeholder="8554"></div></div></details>
        <p><button>Connect</button> <span id="bmsg"></span></p></form></details>
    </div>
    <p class="small muted">This server: <b>${esc(f.serverName)}</b> · ID <code>${esc(f.serverUid)}</code> · CA fingerprint <code>${esc(f.caFingerprint.slice(0, 16))}…</code></p>`;

  $('#inv').onsubmit = async e => {
    e.preventDefault();
    try {
      const r = await api('POST', 'federation/invite', { label: e.target.label.value });
      $('#invOut').innerHTML = `<label>Invite code – send it to the other administrator</label><textarea readonly id="code">${esc(r.code)}</textarea>
        <p><button class="small" id="cpcode">Copy code</button></p>`;
      $('#cpcode').onclick = () => copy(r.code);
    } catch (err) { fail(err); }
  };
  $('#join').onsubmit = async e => {
    e.preventDefault();
    const btn = e.target.querySelector('button');
    btn.disabled = true; $('#joinMsg').innerHTML = '<span class="muted">connecting …</span>';
    try {
      const r = await api('POST', 'federation/join', Object.fromEntries(new FormData(e.target)));
      toast('Linked with ' + r.peerName); route();
    } catch (err) { $('#joinMsg').innerHTML = `<span class="err">${esc(err.message)}</span>`; btn.disabled = false; }
  };
  $('#bf').onsubmit = async e => {
    e.preventDefault();
    const fm = e.target, btn = fm.querySelector('button');
    const num = n => +fm[n].value || 0;
    btn.disabled = true; $('#bmsg').innerHTML = '<span class="muted">connecting …</span>';
    try {
      const r = await api('POST', 'bridges', { host: fm.host.value, name: fm.name.value, username: fm.username.value, password: fm.password.value,
        tls: fm.tls.checked, importVideo: fm.importVideo.checked, exportVideo: fm.exportVideo.checked, streamPort: num('streamPort'),
        enrollPort: num('enrollPort'), apiPort: num('apiPort'), webPort: num('webPort'), rtspPort: num('rtspPort') });
      toast('Connected to ' + r.name); route();
    } catch (err) { $('#bmsg').innerHTML = `<span class="err">${esc(err.message)}</span>`; btn.disabled = false; }
  };
  app.querySelectorAll('tr[data-bid] [data-b]').forEach(btn => btn.onclick = async () => {
    const id = btn.closest('tr').dataset.bid;
    const b = bridges.find(x => x.id === id);
    if (btn.dataset.b === 'toggle') { await api('PUT', 'bridges/' + id, { enabled: !b.enabled }).catch(fail); setTimeout(route, 500); }
    if (btn.dataset.b === 'del') { if (confirm('Remove the connection to ' + b.name + '?')) { await api('DELETE', 'bridges/' + id).catch(fail); route(); } }
    if (btn.dataset.b === 'edit') {
      modal(`<h2>${esc(b.name)}</h2><form id="bef">
        <label>Name of this server there (callsign of the bridge)</label><input type="text" name="callsign" value="${esc(b.callsign)}">
        <label>Share devices of these groups (none checked = all). Data from ${esc(b.name)} is shown to these groups.</label>${groupPicker(groups, b.groups || [])}
        <label class="check"><input type="checkbox" name="importVideo" ${b.importVideo ? 'checked' : ''}> Show its video streams here</label>
        <label class="check"><input type="checkbox" name="exportVideo" ${b.exportVideo ? 'checked' : ''}> Share our video streams there</label>
        <p><button>Save</button></p></form>`);
      $('#bef').onsubmit = async e => {
        e.preventDefault();
        const fm = e.target;
        try {
          await api('PUT', 'bridges/' + id, { callsign: fm.callsign.value, importVideo: fm.importVideo.checked, exportVideo: fm.exportVideo.checked,
            groups: [...fm.querySelectorAll('[name=g]:checked')].map(x => x.value) });
          closeModal(); route();
        } catch (err) { fail(err); }
      };
    }
  });
  app.querySelectorAll('[data-inv]').forEach(b => b.onclick = async () => { await api('DELETE', 'federation/invites/' + b.dataset.inv).catch(fail); route(); });
  app.querySelectorAll('tr[data-id] [data-a]').forEach(b => b.onclick = async () => {
    const id = b.closest('tr').dataset.id;
    const l = f.links.find(x => x.id === id);
    if (b.dataset.a === 'toggle') { await api('PUT', 'federation/links/' + id, { enabled: !l.enabled }).catch(fail); setTimeout(route, 400); }
    if (b.dataset.a === 'del') {
      if (!confirm(`Remove the link to ${l.peerName}? To link again you need a new invite.`)) return;
      await api('DELETE', 'federation/links/' + id).catch(fail); route();
    }
    if (b.dataset.a === 'edit') {
      modal(`<h2>Link to ${esc(l.peerName)}</h2><form id="lf">
        <label>Share devices of these groups (none checked = all groups). Data from ${esc(l.peerName)} is shown to these groups.</label>
        ${groupPicker(groups, l.groups || [])}
        <label class="check"><input type="checkbox" name="transit" ${l.transit ? 'checked' : ''}> Also pass on data of further linked servers (chains like A – B – C)</label>
        <p><button>Save</button></p></form>`);
      $('#lf').onsubmit = async e => {
        e.preventDefault();
        const gs = [...e.target.querySelectorAll('[name=g]:checked')].map(x => x.value);
        try { await api('PUT', 'federation/links/' + id, { groups: gs, transit: e.target.transit.checked }); closeModal(); route(); } catch (err) { fail(err); }
      };
    }
  });
  // refresh the status, but never while the admin is copying or pasting a code
  timer = setInterval(() => { if (!document.hidden && $('#modal').hidden && !$('#invOut').innerHTML && !$('#join').code.value.trim() && !$('#bf').host.value) route(); }, 15000);
}

// ---------------------------------------------------------------- data packages

async function pagePackages() {
  const list = await api('GET', 'packages');
  app.innerHTML = `<h1>Data packages</h1>
    <p class="muted">Files shared through the server. "Public" packages appear in ATAK/WinTAK under Data Packages → server.</p>
    <div class="card"><form id="up" class="row"><input type="file" name="file" required><button>Upload</button></form></div>
    <div class="card table-wrap"><table><tr><th>Name</th><th>Size</th><th>From</th><th>Uploaded</th><th>Visible</th><th></th></tr>
    ${list.map(p => `<tr><td><b>${esc(p.name)}</b><div class="small muted">${esc(p.hash.slice(0, 16))}…</div></td><td>${bytes(p.size)}</td>
      <td>${esc(p.user || '')}<div class="small muted">${esc(p.origin)}</div></td><td>${ago(p.submitted)}</td>
      <td><button class="small ghost" data-tool="${esc(p.hash)}" data-v="${p.tool === 'public' ? 'private' : 'public'}">${p.tool === 'public' ? 'public' : 'private'}</button></td>
      <td class="row"><a class="btn small ghost" href="/admin/api/packages/${esc(p.hash)}">Download</a><button class="small danger" data-del="${esc(p.hash)}">Delete</button></td></tr>`).join('')
      || '<tr><td colspan="6" class="muted">No data packages yet.</td></tr>'}</table></div>`;
  $('#up').onsubmit = async e => {
    e.preventDefault();
    try { await api('POST', 'packages', new FormData(e.target)); route(); } catch (err) { fail(err); }
  };
  app.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { if (confirm('Delete this package?')) { await api('DELETE', 'packages/' + b.dataset.del).catch(fail); route(); } });
  app.querySelectorAll('[data-tool]').forEach(b => b.onclick = async () => { await api('PUT', 'packages/' + b.dataset.tool, { tool: b.dataset.v }).catch(fail); route(); });
}

// ---------------------------------------------------------------- video

async function pageVideo() {
  const render = async () => {
    const v = await api('GET', 'video');
    const ok = v.running;
    const kindName = { pushed: 'camera / drone', pulled: 'pulled', federation: 'federated server', bridge: 'TAK server', link: 'link only' };
    const linkBtns = l => !l ? '' : Object.entries(l).map(([k, u]) =>
      `<button class="small ghost" data-copy="${esc(u)}" title="${esc(u)}">${k.toUpperCase()}</button>`).join('');
    app.innerHTML = `<div class="row spread"><h1>Video</h1><span>${ok ? '<span class="dot ok"></span>video server running' :
      `<span class="dot ${v.enabled ? 'bad' : ''}"></span>${esc(v.status)}`}</span></div>
      <p class="muted">Built-in video server (MediaMTX ${esc(v.version)}, as in OpenTAKServer). Cameras, drones and phones send video here;
      ATAK, iTAK and WinTAK find every stream under <b>Video → server feeds</b>. Streams of federated servers and linked TAK servers appear automatically.</p>
      ${v.enabled ? '' : '<p class="hint">The video server is switched off – <a href="#settings">Settings</a>.</p>'}
      <div class="card table-wrap"><h2>Streams</h2><table>
      <tr><th>Name</th><th>Type</th><th>Status</th><th>Links (click to copy)</th><th></th></tr>
      ${v.feeds.map(f => `<tr><td><b>${esc(f.alias)}</b>${f.path ? `<div class="small muted"><code>${esc(f.path)}</code></div>` : ''}
          ${f.source ? `<div class="small muted">from ${esc(f.source)}</div>` : ''}${f.url ? `<div class="small"><code>${esc(f.url)}</code></div>` : ''}</td>
        <td>${esc(kindName[f.kind] || f.kind)}</td>
        <td>${f.kind === 'link' ? '–' : f.live ? `<span class="dot ok"></span>live${f.readers ? ' · ' + f.readers + ' watching' : ''}` :
          (f.kind === 'pushed' ? '<span class="dot"></span>waiting for the camera' : '<span class="dot"></span>starts when someone watches')}</td>
        <td class="row">${linkBtns(f.links)}${f.links && f.links.webrtc ? `<a class="btn small" target="_blank" rel="noopener" href="${esc(f.links.webrtc)}">▶ Watch</a>` : ''}</td>
        <td>${f.configured ? `<button class="small danger" data-del="${esc(f.kind === 'link' ? 'links/' + f.uid : 'streams/' + f.path)}">Delete</button>` : ''}</td></tr>`).join('')
        || '<tr><td colspan="5" class="muted">No streams yet. Send video to the server (below) – it appears here by itself.</td></tr>'}
      </table></div>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(320px,1fr))">
      <div class="card"><h2>Send video to the server</h2>
        <p class="small">Use any name instead of <code>drone-1</code> and the user name / password of a TAK user (here: you).</p>
        <label>DJI drone (DJI Fly / Pilot 2: Livestream → RTMP), OBS, Larix</label><code class="code">${esc(v.publish.rtmp || 'RTMP is off')}</code>
        <label>RTSP (IP cameras, ffmpeg, Larix)</label><code class="code">${esc(v.publish.rtsp || 'RTSP is off')}</code>
        <label>SRT (OBS, Larix, long distance / mobile networks)</label><code class="code">${esc(v.publish.srt || 'SRT is off')}</code>
        <p class="small muted">Ports: RTSP ${v.ports.rtsp}, RTMP ${v.ports.rtmp}, SRT ${v.ports.srt} (UDP), HLS ${v.ports.hls}, WebRTC ${v.ports.webrtc}.
        ${v.readAuth ? 'Watching needs a login.' : 'Watching is open to everyone who can reach the server (change under Settings).'}</p></div>
      <div class="card"><h2>Add a stream</h2>
        <form id="sf"><label>Name (path), e.g. <code>gate-camera</code></label><input type="text" name="path" required>
        <label>Display name (optional)</label><input type="text" name="alias">
        <label>Pull from (optional) – rtsp://, rtmp://, srt://, udp:// or https://…/index.m3u8. Empty = a camera sends to this name.</label>
        <input type="text" name="source" placeholder="rtsp://user:password@192.168.1.50:554/stream1">
        <p class="small muted">Pulled streams only run while someone watches.</p><p><button>Add stream</button></p></form>
        <hr style="border:0;border-top:1px solid var(--line)">
        <form id="lf"><label>Or only list a link to video elsewhere (not through this server)</label>
        <div class="row"><input type="text" name="alias" placeholder="Name" style="flex:1"><input type="text" name="url" placeholder="rtsp://…" style="flex:2" required><button>Add link</button></div></form>
      </div></div>`;
    app.querySelectorAll('[data-copy]').forEach(b => b.onclick = () => copy(b.dataset.copy));
    app.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
      if (!confirm('Delete this stream?')) return;
      await api('DELETE', 'video/' + b.dataset.del.split('/').map(encodeURIComponent).join('/')).catch(fail); render();
    });
    $('#sf').onsubmit = async e => {
      e.preventDefault();
      try { await api('POST', 'video/streams', Object.fromEntries(new FormData(e.target))); toast('Stream added'); render(); } catch (err) { fail(err); }
    };
    $('#lf').onsubmit = async e => {
      e.preventDefault();
      try { await api('POST', 'video/links', Object.fromEntries(new FormData(e.target))); render(); } catch (err) { fail(err); }
    };
  };
  await render();
  timer = setInterval(() => { if (!document.hidden && !document.activeElement.closest('form')) render().catch(() => {}); }, 5000);
}

// ---------------------------------------------------------------- settings

async function pageSettings() {
  const s = await api('GET', 'settings');
  app.innerHTML = `<h1>Settings</h1><form id="sf">
    <div class="card"><h2>Server</h2>
      <label>Server name</label><input type="text" name="serverName" value="${esc(s.serverName)}">
      <label>Address for the devices (DNS name or IP; empty = automatic local address)</label>
      <input type="text" name="publicHost" value="${esc(s.publicHost)}" placeholder="automatic">
      <p class="small muted">Used in QR codes, connection packages and federation invites. The server certificate is renewed automatically.</p>
    </div>
    <div class="card"><h2>Devices</h2>
      <label class="check"><input type="checkbox" name="enableTcp" ${s.enableTcp ? 'checked' : ''}> Unencrypted TCP port 8088 without login (simple, but anyone in the network can join – restart needed)</label>
      <label class="check"><input type="checkbox" name="anonHttp" ${s.anonHttp ? 'checked' : ''}> Data packages over plain HTTP port 8080 without login (needed by TCP devices)</label>
      <label class="check"><input type="checkbox" name="sendLatestSa" ${s.sendLatestSa ? 'checked' : ''}> Newly connected devices immediately get the positions of everyone online</label>
      <label>Password of the certificate files (.p12) in connection packages</label><input type="text" name="certPassword" value="${esc(s.certPassword)}">
      <label>Keep contacts on the map for (minutes after their last report)</label><input type="number" name="contactMaxAge" value="${s.contactMaxAge}" min="1">
    </div>
    <div class="card"><h2>Video server</h2>
      <label class="check"><input type="checkbox" name="videoEnabled" ${s.videoEnabled ? 'checked' : ''}> Run the video server (MediaMTX – RTSP 8554, RTMP 1935, SRT 8890, HLS 8888, WebRTC 8889)</label>
      <label class="check"><input type="checkbox" name="videoReadAuth" ${s.videoReadAuth ? 'checked' : ''}> Watching needs a login (sending always does). Leave off if ATAK should play streams without a password.</label>
      <label class="check"><input type="checkbox" name="videoFedShare" ${s.videoFedShare ? 'checked' : ''}> Exchange video with federated servers</label>
      <label>MediaMTX program (optional – empty = automatic: next to webtak-server, or downloaded on first start)</label>
      <input type="text" name="mediamtxPath" value="${esc(s.mediamtxPath)}" placeholder="automatic">
    </div>
    <div class="card"><h2>Meshtastic radios (MQTT)</h2>
      <label class="check"><input type="checkbox" name="mqttOn" ${s.mqttOn ? 'checked' : ''}> MQTT broker for Meshtastic radios with TLS (port 8883 – restart needed)</label>
      <label class="check"><input type="checkbox" name="mqttPlain" ${s.mqttPlain ? 'checked' : ''}> Also without TLS (port 1883 – only inside a closed network; restart needed)</label>
    </div>
    <div class="card"><h2>Federation and TAK server bridges</h2>
      <label class="check"><input type="checkbox" name="fedEnabled" ${s.fedEnabled ? 'checked' : ''}> Accept connections from linked servers</label>
      <label>Position of this server (shown as a marker on linked TAK servers) – latitude, longitude</label>
      <div class="row"><input type="number" step="any" name="lat" value="${s.lat}" style="flex:1"><input type="number" step="any" name="lon" value="${s.lon}" style="flex:1"></div>
    </div>
    <div class="card"><h2>Own certificate for the web interface (optional)</h2>
      <p class="small muted">E.g. Let's Encrypt (certbot) – removes the browser warning when the server is opened by its DNS name. Devices keep using the server's own CA.</p>
      <label>Certificate file (fullchain.pem)</label><input type="text" name="webCert" value="${esc(s.webCert)}" placeholder="/etc/letsencrypt/live/tak.example.com/fullchain.pem">
      <label>Key file (privkey.pem)</label><input type="text" name="webKey" value="${esc(s.webKey)}" placeholder="/etc/letsencrypt/live/tak.example.com/privkey.pem">
    </div>
    <p><button>Save settings</button></p></form>
    <div class="card"><h2>Certificates</h2>
      <p class="small">CA of this server, for devices you set up by hand: <a href="/admin/api/truststore">truststore.p12</a> (password as above) · <a href="/admin/api/ca.pem">ca.pem</a></p>
      <p class="small muted">Data folder: <code>${esc(s.dataDir)}</code> – back it up to keep users, certificates and links.</p></div>`;
  $('#sf').onsubmit = async e => {
    e.preventDefault();
    const f = e.target;
    const body = { serverName: f.serverName.value, publicHost: f.publicHost.value, enableTcp: f.enableTcp.checked, anonHttp: f.anonHttp.checked,
      sendLatestSa: f.sendLatestSa.checked, certPassword: f.certPassword.value, contactMaxAge: +f.contactMaxAge.value, fedEnabled: f.fedEnabled.checked,
      webCert: f.webCert.value, webKey: f.webKey.value, videoEnabled: f.videoEnabled.checked, videoReadAuth: f.videoReadAuth.checked,
      videoFedShare: f.videoFedShare.checked, mediamtxPath: f.mediamtxPath.value, lat: +f.lat.value, lon: +f.lon.value,
      mqttOn: f.mqttOn.checked, mqttPlain: f.mqttPlain.checked };
    try { const r = await api('PUT', 'settings', body); toast(r.restart ? 'Saved – restart the server to apply the port change' : 'Saved'); route(); } catch (err) { fail(err); }
  };
}

async function pageLog() {
  const render = async () => {
    const lines = await api('GET', 'logs');
    app.innerHTML = `<h1>Log</h1><div class="log" id="log">${esc(lines.slice().reverse().join('\n'))}</div>`;
  };
  await render();
  timer = setInterval(() => { if (!document.hidden) render().catch(() => {}); }, 5000);
}

route();
