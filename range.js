'use strict';
// =====================================================================
// Simulated network: every command emits real, well-formed packets
// (valid IPv4/TCP/UDP checksums, TCP sequence numbers, DNS and SNMP
// encodings) so the exported .pcap opens cleanly in Wireshark/PacketStory.
// =====================================================================
const A = '10.0.0.5', T = '10.0.0.9', P = [];
const MAC = { [A]: [2, 0, 0, 0, 0, 5], [T]: [2, 0, 0, 0, 0, 9] };
const T0 = Math.floor(Date.now() / 1000);
let clock = 0, ipid = 1;
const ipb = s => s.split('.').map(Number);
const enc = s => typeof s === 'string' ? new TextEncoder().encode(s) : s;
const rnd = n => Math.floor(Math.random() * n);

function csum(b, s, e, init = 0) {
  let x = init;
  for (let i = s; i < e; i += 2) x += (b[i] << 8) | (i + 1 < e ? b[i + 1] : 0);
  while (x >> 16) x = (x & 0xffff) + (x >> 16);
  return ~x & 0xffff;
}
// Ethernet + IPv4 + L4 header (l4 bytes) + payload; fill(view) writes the L4 header
function frame(pr, s, d, l4, data, fill) {
  clock += 0.0004 + Math.random() * 0.004;
  const h = 34 + l4, b = new Uint8Array(h + data.length), v = new DataView(b.buffer);
  b.set(MAC[d] || [2, 0, 0, 0, 0, 1], 0); b.set(MAC[s] || [2, 0, 0, 0, 0, 1], 6); v.setUint16(12, 0x0800);
  b[14] = 0x45; v.setUint16(16, 20 + l4 + data.length); v.setUint16(18, ipid++ & 0xffff); v.setUint16(20, 0x4000);
  b[22] = 64; b[23] = pr; b.set(ipb(s), 26); b.set(ipb(d), 30);
  v.setUint16(24, csum(b, 14, 34));
  b.set(data, h); fill(v);
  // pseudo-header checksum for TCP/UDP
  const len = l4 + data.length;
  let ph = (b[26] << 8 | b[27]) + (b[28] << 8 | b[29]) + (b[30] << 8 | b[31]) + (b[32] << 8 | b[33]) + pr + len;
  const ck = csum(b, 34, 34 + len, ph);
  v.setUint16(pr === 6 ? 50 : 40, pr === 17 && ck === 0 ? 0xffff : ck);
  P.push({ t: T0 + clock, b });
}
function tcp(s, d, sp, dp, fl, pl = '', seq = 0, ack = 0) {
  const data = enc(pl);
  frame(6, s, d, 20, data, v => { v.setUint16(34, sp); v.setUint16(36, dp); v.setUint32(38, seq >>> 0); v.setUint32(42, ack >>> 0); v.setUint8(46, 0x50); v.setUint8(47, fl); v.setUint16(48, 64240); });
  return data.length;
}
function udp(s, d, sp, dp, pl) {
  const data = enc(pl);
  frame(17, s, d, 8, data, v => { v.setUint16(34, sp); v.setUint16(36, dp); v.setUint16(38, 8 + data.length); });
}
// full TCP conversation: handshake, exchanges [['c'|'s', payload]], graceful close
function sess(dp, ex, sp = 40000 + rnd(20000)) {
  let c = rnd(2 ** 31), s = rnd(2 ** 31);
  tcp(A, T, sp, dp, 0x02, '', c); tcp(T, A, dp, sp, 0x12, '', s, c + 1); c++; s++; tcp(A, T, sp, dp, 0x10, '', c, s);
  for (const [w, x] of ex) {
    if (w === 'c') { c += tcp(A, T, sp, dp, 0x18, x, c, s); tcp(T, A, dp, sp, 0x10, '', s, c); }
    else { s += tcp(T, A, dp, sp, 0x18, x, s, c); tcp(A, T, sp, dp, 0x10, '', c, s); }
  }
  tcp(A, T, sp, dp, 0x11, '', c, s); tcp(T, A, dp, sp, 0x11, '', s, c + 1); tcp(A, T, sp, dp, 0x10, '', c + 1, s + 1);
}
function pcap() {
  const o = new Uint8Array(P.reduce((a, p) => a + 16 + p.b.length, 24)), v = new DataView(o.buffer);
  v.setUint32(0, 0xa1b2c3d4, true); v.setUint16(4, 2, true); v.setUint16(6, 4, true); v.setUint32(16, 65535, true); v.setUint32(20, 1, true);
  let k = 24;
  for (const p of P) { const s = Math.floor(p.t); v.setUint32(k, s, true); v.setUint32(k + 4, Math.floor((p.t - s) * 1e6), true); v.setUint32(k + 8, p.b.length, true); v.setUint32(k + 12, p.b.length, true); o.set(p.b, k + 16); k += 16 + p.b.length; }
  return o;
}

// ---- DNS encoding ----
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
const u16 = n => [n >> 8 & 255, n & 255], u32 = n => [n >>> 24 & 255, n >> 16 & 255, n >> 8 & 255, n & 255];
const dname = n => cat(...n.replace(/\.$/, '').split('.').filter(Boolean).map(l => cat([l.length], enc(l))), [0]);
const QTYPE = { A: 1, NS: 2, SOA: 6, TXT: 16, AXFR: 252 };
function dnsMsg(id, flags, q, qt, answers = []) {
  return cat(new Uint8Array([...u16(id), ...u16(flags), 0, 1, ...u16(answers.length), 0, 0, 0, 0]), dname(q), new Uint8Array([...u16(QTYPE[qt]), 0, 1]), ...answers);
}
function rr(name, type, data) {
  const rd = type === 'A' ? new Uint8Array(ipb(data)) : type === 'NS' ? dname(data) : type === 'TXT' ? cat([data.length], enc(data))
    : cat(dname(data[0]), dname(data[1]), new Uint8Array([...u32(data[2]), ...u32(3600), ...u32(600), ...u32(86400), ...u32(3600)]));
  return cat(dname(name), new Uint8Array([...u16(QTYPE[type]), 0, 1, ...u32(3600), ...u16(rd.length)]), rd);
}
const tcpDns = m => cat(u16(m.length), m);

// ---- SNMP (BER) encoding ----
const tlv = (tag, body) => { const l = body.length; return cat([tag], l < 128 ? [l] : l < 256 ? [0x81, l] : [0x82, l >> 8, l & 255], body); };
const bint = n => tlv(0x02, n === 0 ? [0] : (() => { const a = []; let x = n; while (x > 0) { a.unshift(x & 255); x = Math.floor(x / 256); } if (a[0] & 0x80) a.unshift(0); return a; })());
const boid = s => { const p = s.split('.').map(Number), o = [40 * p[0] + p[1]]; for (const n of p.slice(2)) { const t = [n & 127]; let x = n >> 7; while (x) { t.unshift(x & 127 | 128); x >>= 7; } o.push(...t); } return tlv(0x06, o); };
function snmpMsg(pdu, community, reqid, oid, value) {
  const vb = tlv(0x30, cat(boid(oid), value === undefined ? new Uint8Array([5, 0]) : tlv(0x04, enc(value))));
  return tlv(0x30, cat(bint(1), tlv(0x04, enc(community)), tlv(pdu, cat(bint(reqid), bint(0), bint(0), tlv(0x30, vb)))));
}

// =====================================================================
// Game content
// =====================================================================
const SV = { 21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3', 111: 'rpcbind', 139: 'netbios-ssn', 143: 'imap', 445: 'microsoft-ds', 2049: 'nfs', 3306: 'mysql' };
const FLAGS = { 'FLAG{anonymous_ftp_is_a_risk}': 'ftp', 'FLAG{robots_txt_reveals_paths}': 'http', 'FLAG{null_session_lists_the_shares}': 'smb', 'FLAG{nfs_exports_everyone}': 'nfs', 'FLAG{zone_transfer_leaks_the_map}': 'dns', 'FLAG{banners_talk_too_much}': 'smtp', 'FLAG{community_strings_are_passwords}': 'snmp', 'FLAG{leaked_creds_open_the_database}': 'mysql', 'FLAG{mailboxes_hold_secrets}': 'imap', 'FLAG{reused_creds_get_you_in}': 'ssh' };
const ORDER = ['ftp', 'http', 'smb', 'nfs', 'dns', 'smtp', 'snmp', 'mysql', 'imap', 'ssh'], TOTAL = ORDER.length;
const FS = { pub: { 'readme.txt': 'Welcome to the files01 public FTP.\nFLAG{anonymous_ftp_is_a_risk}\nOld backups live in /backup.' }, backup: { 'notes.txt': 'TODO: rotate the admin password.\nssh user: admin   password: Summer2026!' } };
const SMB = { 'it-notes.txt': 'IT notes\nFLAG{null_session_lists_the_shares}\nInternal domain: corp.local\nMail backup account: backup / Backup2026!' };
const NFS = { 'deploy-notes.txt': 'Deploy notes\nFLAG{nfs_exports_everyone}\nExports are open to all hosts. TODO: restrict.' };
const HOME = { 'flag.txt': 'FLAG{reused_creds_get_you_in}', 'todo.txt': '- patch the ftp server\n- stop reusing passwords' };
const WEB = { '/': 'files01 internal portal\n(nothing to see here)', '/robots.txt': 'User-agent: *\nDisallow: /secret.txt', '/secret.txt': 'FLAG{robots_txt_reveals_paths}' };
const BAN = { 21: '220 files01 FTP ready', 22: 'SSH-2.0-OpenSSH_9.6', 25: '220 mail.corp.local ESMTP Postfix FLAG{banners_talk_too_much}', 110: '+OK POP3 ready', 143: '* OK IMAP4rev1 ready' };
const ZONE = [['corp.local', 'SOA', ['ns1.corp.local', 'admin.corp.local', 2026102901]], ['corp.local', 'NS', 'ns1.corp.local'], ['ns1.corp.local', 'A', '10.0.0.9'], ['mail.corp.local', 'A', '10.0.0.9'], ['vpn.corp.local', 'A', '10.0.0.77'], ['dev-internal.corp.local', 'A', '10.0.0.88'], ['flag.corp.local', 'TXT', 'FLAG{zone_transfer_leaks_the_map}']];
const zoneText = () => ZONE.map(([n, t, d]) => (n + '.').padEnd(26) + '3600 IN ' + t.padEnd(5) + (t === 'SOA' ? d[0] + '. ' + d[1] + '. ' + d[2] + ' 3600 600 86400 3600' : t === 'TXT' ? '"' + d + '"' : d + (t === 'NS' ? '.' : ''))).join('\n');
const SNMPW = [['1.3.6.1.2.1.1.1.0', 'SNMPv2-MIB::sysDescr.0', 'Linux files01 6.8.0'], ['1.3.6.1.2.1.1.4.0', 'SNMPv2-MIB::sysContact.0', 'admin@corp.local'], ['1.3.6.1.2.1.1.5.0', 'SNMPv2-MIB::sysName.0', 'files01'], ['1.3.6.1.2.1.1.6.0', 'SNMPv2-MIB::sysLocation.0', 'Rack 4 FLAG{community_strings_are_passwords}'], ['1.3.6.1.2.1.25.4.2.1.2.812', 'HOST-RESOURCES-MIB::hrSWRunName.812', '"dbsync"'], ['1.3.6.1.2.1.25.4.2.1.5.812', 'HOST-RESOURCES-MIB::hrSWRunParameters.812', '"--user dbadmin --password Db#Pass2026 --db app"']];
const HINTS = {
  ftp: ['FTP servers sometimes allow anonymous logins.', 'ftp 10.0.0.9, name: anonymous, any password.', 'ls and cd into every directory, get the files, then exit and cat them locally.'],
  http: ['Websites tell crawlers what not to index.', 'Crawlers read one file first: robots.txt.', 'curl 10.0.0.9/robots.txt, then curl the disallowed path.'],
  smb: ['SMB shares can sometimes be listed without a password (a null session).', 'smbclient -L //10.0.0.9 -N lists the shares. Connect to one with smbclient //10.0.0.9/<share> -N.', 'Inside the share: ls, get <file>, exit, then cat the file.'],
  nfs: ['NFS exports can be listed with a tool from the nfs-common package.', 'showmount -e 10.0.0.9, then mount -t nfs 10.0.0.9:<export> /mnt/nfs', 'ls /mnt/nfs and cat /mnt/nfs/<file>'],
  dns: ['A DNS server may hand its whole zone to anyone who asks.', 'The query type is AXFR. The domain name is in your downloaded notes.', 'dig axfr corp.local @10.0.0.9'],
  smtp: ['Servers announce themselves when you connect.', 'Grab the banner of the mail port (25) with nc.', 'nc 10.0.0.9 25'],
  snmp: ['SNMP runs over UDP and is often protected only by a community string.', 'Scan UDP first (nmap -sU 10.0.0.9), then try the default community string with snmpwalk.', 'snmpwalk -v2c -c public 10.0.0.9 and read every line, especially the process list.'],
  mysql: ['Credentials leak in odd places, like process lists.', 'Use the credentials from the SNMP output: mysql -h 10.0.0.9 -u dbadmin -p', 'show databases; use app; show tables; select * from secrets;'],
  imap: ['Admins keep backup mail accounts with weak passwords. Check your SMB notes.', 'curl can read mail over IMAP: curl imap://10.0.0.9/INBOX --user name:password', 'curl imap://10.0.0.9/INBOX --user backup:Backup2026!'],
  ssh: ['Credentials found earlier may be reused.', 'The FTP backup notes contain a username and password.', 'ssh admin@10.0.0.9, then ls and cat flag.txt']
};
const CMDS = ['help', 'nmap', 'ftp', 'smbclient', 'showmount', 'mount', 'dig', 'nc', 'snmpwalk', 'mysql', 'curl', 'ssh', 'ls', 'cat', 'submit', 'hint', 'status', 'capture', 'analyze', 'history', 'whoami', 'ifconfig', 'clear', 'reset', 'loot', 'debrief', 'explain'];

// =====================================================================
// Terminal
// =====================================================================
const $ = s => document.querySelector(s), t = $('#t'), inp = $('#i'), pr = $('#p');
const local = /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
const PCAP = local ? 'http://' + location.hostname + ':8002' : 'https://pcap.0vuln.com';
let mode = 'sh', found = new Set(), files = {}, rc = [], ft = null, fl = null, ask = null, hist = [], hp = 0, mounted = false, db = '', hc = {}, started = 0, finished = 0;
const store = { get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } }, set: (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* storage blocked */ } } };
found = new Set(store.get('range', []).filter(f => FLAGS[f]));
started = store.get('range-start', 0); finished = store.get('range-end', 0);
hist = store.get('range-hist', []); hp = hist.length;
let loot = store.get('range-loot', []);
const save = () => { store.set('range', [...found]); store.set('range-start', started); store.set('range-end', finished); };

const out = (x, c = '') => { const d = document.createElement('div'); d.textContent = x; d.className = c; t.appendChild(d); t.scrollTop = t.scrollHeight; if (!c) collect(String(x)); };
// write down anything useful that appears in normal output (hints are class 'd', so they never count)
function collect(text) {
  let added = 0;
  for (const [re, fmt] of LOOT) { const m = text.match(re); if (m) { const item = fmt(m); if (!loot.includes(item)) { loot.push(item); added++; } } }
  if (added) { store.set('range-loot', loot); lootPanel(); window.OV && OV.toast('Added to your loot notebook'); }
}
function lootPanel() {
  const ul = $('#loot'); if (!ul) return;
  $('#loot-n').textContent = loot.length ? loot.length + ' found' : '';
  ul.innerHTML = loot.length ? loot.map(l => '<li>' + l.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])) + '</li>').join('') : '<li class="empty">Credentials and clues you uncover are written down here automatically.</li>';
}
const promptStr = () => ({ sh: 'attacker@kali:~$', ft: ft && ft.p === 'smb' ? 'smb: \\>' : 'ftp>', ssh: 'admin@files01:~$', sql: db ? 'mysql [' + db + ']>' : 'mysql>' })[mode];
const setp = () => { pr.textContent = ask ? ask.q : promptStr(); inp.type = ask && ask.hide ? 'password' : 'text'; };
const flushFtp = () => { if (fl) { sess(ft.port, fl); fl = null; } };
const done = s => [...found].some(f => FLAGS[f] === s);

const PORTS = { ftp: 21, http: 80, smb: 445, nfs: 2049, dns: 53, smtp: 25, snmp: 161, mysql: 3306, imap: 143, ssh: 22 };
function panel() {
  $('#score').textContent = found.size + '/' + TOTAL;
  const ring = $('#ring'), C = 2 * Math.PI * 52;
  ring.style.strokeDasharray = C.toFixed(1); ring.style.strokeDashoffset = (C * (1 - found.size / TOTAL)).toFixed(1);
  $('#flags').innerHTML = ORDER.map(s => '<li class="' + (done(s) ? 'on' : '') + '"><button type="button" data-run="' + (done(s) ? 'debrief ' : 'hint ') + s + '" title="' + (done(s) ? s + ': captured, click for the debrief' : 'hint for ' + s) + '"><b>' + s + '</b><span>' + (done(s) ? 'pwned' : PORTS[s] + (s === 'snmp' ? '/udp' : '/tcp')) + '</span></button></li>').join('');
}
const fmtTime = ms => { const s = Math.floor(ms / 1000); return (s >= 3600 ? Math.floor(s / 3600) + 'h ' : '') + String(Math.floor(s / 60) % 60).padStart(2, '0') + 'm ' + String(s % 60).padStart(2, '0') + 's'; };
setInterval(() => { $('#timer').textContent = !started ? 'not started' : fmtTime((finished || Date.now()) - started) + (finished ? ' (done)' : ''); $('#pkts').textContent = P.length.toLocaleString(); }, 500);

function sh(c, a) {
  switch (c) {
    case 'help':
      out('recon      nmap [-sU] <ip>   nc <ip> <port>   dig [axfr] <domain> @<ip>   showmount -e <ip>', 'd');
      out('services   ftp <ip>   smbclient -L //<ip> -N   mount -t nfs <ip>:<export> /mnt/nfs   snmpwalk -v2c -c <community> <ip>', 'd');
      out('           mysql -h <ip> -u <user> -p   curl <url>   ssh <user>@<ip>', 'd');
      out('loot       ls   cat <file>   submit FLAG{...}', 'd');
      out('learn      explain <command>   debrief [service]   loot', 'd');
      out('game       hint [service]   status   capture   analyze   history   reset   clear', 'd');
      out('Tab completes, arrow keys walk your history.', 'c'); break;
    case 'whoami': out('attacker'); break;
    case 'ifconfig': case 'ip': out('eth0: inet 10.0.0.5  netmask 255.255.255.0  ether 02:00:00:00:00:05'); break;
    case 'history': out(hist.map((h, i) => String(i + 1).padStart(4) + '  ' + h).join('\n') || '(empty)', 'd'); break;
    case 'nmap': {
      if (!a.includes(T)) { out('Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn', 'e'); break; }
      if (a.includes('-sU')) {
        const id = rnd(65535);
        for (const p of [53, 67, 69, 123, 137, 161, 500]) {
          const probe = p === 53 ? dnsMsg(id, 0x0100, 'version.bind', 'TXT') : p === 161 ? snmpMsg(0xa0, 'public', id, '1.3.6.1.2.1.1.1.0') : new Uint8Array(0);
          udp(A, T, 50000 + p, p, probe);
          if (p === 53) udp(T, A, p, 50000 + p, dnsMsg(id, 0x8105, 'version.bind', 'TXT'));
          if (p === 161) udp(T, A, p, 50000 + p, snmpMsg(0xa2, 'public', id, '1.3.6.1.2.1.1.1.0', 'Linux files01 6.8.0'));
        }
        out('Nmap scan report for files01 (10.0.0.9)\nPORT    STATE SERVICE\n53/udp  open  domain\n161/udp open  snmp'); break;
      }
      const sp = 40000 + rnd(20000);
      for (const p of [...Array(1024).keys()].map(i => i + 1).concat([2049, 3306])) {
        const s = rnd(2 ** 31); tcp(A, T, sp, p, 0x02, '', s);
        if (SV[p]) { tcp(T, A, p, sp, 0x12, '', rnd(2 ** 31), s + 1); tcp(A, T, sp, p, 0x04, '', s + 1); } else tcp(T, A, p, sp, 0x14, '', 0, s + 1);
      }
      out('Starting Nmap 7.95 ( https://nmap.org )\nNmap scan report for files01 (10.0.0.9)\nNot shown: 1014 closed tcp ports (reset)\nPORT      STATE SERVICE\n' + Object.keys(SV).map(p => (p + '/tcp').padEnd(10) + 'open  ' + SV[p]).join('\n') + '\nNmap done: 1 IP address (1 host up) scanned'); break;
    }
    case 'ftp':
      if (a[0] !== T) { out('ftp: connect: Connection refused', 'e'); break; }
      ft = { t: FS, p: 'ftp', port: 21 }; fl = [['s', '220 files01 FTP ready\r\n']]; out('Connected to 10.0.0.9.\n220 files01 FTP ready');
      ask = { q: 'Name (10.0.0.9):', cb: u => {
        fl.push(['c', 'USER ' + u + '\r\n']);
        if (!['anonymous', 'ftp'].includes(u)) { fl.push(['s', '530 Login incorrect.\r\n']); out('530 Login incorrect.\nftp: Login failed', 'e'); flushFtp(); return; }
        fl.push(['s', '331 Please specify the password.\r\n']);
        ask = { q: 'Password:', hide: 1, cb: p => { fl.push(['c', 'PASS ' + p + '\r\n'], ['s', '230 Login successful.\r\n']); out('230 Login successful.'); mode = 'ft'; rc = []; } };
      } }; break;
    case 'smbclient': {
      const s = a.join(' '); if (!s.includes('//' + T)) { out('do_connect: Connection to failed (Error NT_STATUS_HOST_UNREACHABLE)', 'e'); break; }
      const m = s.match(/\/\/[\d.]+\/(\S+)/);
      if (!m) { sess(445, [['c', 'SMB2 NEGOTIATE'], ['s', 'SMB2 NEGOTIATE OK'], ['c', 'SMB2 TREE_CONNECT \\\\10.0.0.9\\IPC$'], ['s', 'STATUS_SUCCESS']]);
        out('\tSharename       Type      Comment\n\t---------       ----      -------\n\tprint$          Disk      Printer Drivers\n\tpublic          Disk      Public files\n\tbackups         Disk      Backups (restricted)\n\tIPC$            IPC       IPC Service'); break; }
      if (m[1] !== 'public') { sess(445, [['c', 'SMB2 TREE_CONNECT \\\\10.0.0.9\\' + m[1]], ['s', 'STATUS_ACCESS_DENIED']]); out('tree connect failed: NT_STATUS_ACCESS_DENIED', 'e'); break; }
      ft = { t: SMB, p: 'smb', port: 445 }; fl = [['c', 'SMB2 NEGOTIATE'], ['s', 'SMB2 NEGOTIATE OK'], ['c', 'SMB2 TREE_CONNECT \\\\10.0.0.9\\public'], ['s', 'STATUS_SUCCESS']]; mode = 'ft'; rc = [];
      out('Try "help" to get a list of possible commands.'); break;
    }
    case 'showmount':
      if (!a.includes(T)) { out('clnt_create: RPC: Unable to receive', 'e'); break; }
      sess(111, [['c', 'PORTMAP GETPORT mountd'], ['s', 'port 20048']]); out('Export list for 10.0.0.9:\n/srv/nfs/backups *'); break;
    case 'mount': {
      const s = a.join(' ');
      if (!s.includes(T + ':/srv/nfs/backups') || !s.includes('/mnt/nfs')) { out('mount.nfs: access denied or bad path. Format: mount -t nfs 10.0.0.9:/export /mnt/nfs', 'e'); break; }
      sess(2049, [['c', 'MNT /srv/nfs/backups'], ['s', 'MNT OK']]); mounted = true; out('mounted 10.0.0.9:/srv/nfs/backups on /mnt/nfs'); break;
    }
    case 'dig': {
      const s = a.join(' '), dom = (a.find(x => /corp\.local\.?$/i.test(x)) || '').replace(/\.$/, '');
      if (!s.includes('@' + T)) { out(';; communications error: no servers could be reached (add @10.0.0.9)', 'e'); break; }
      if (!dom) { const q = a.find(x => !x.startsWith('@') && !/^(axfr|a|any)$/i.test(x)) || '.'; const id = rnd(65535), sp = 50000 + rnd(9999); udp(A, T, sp, 53, dnsMsg(id, 0x0100, q, 'A')); udp(T, A, 53, sp, dnsMsg(id, 0x8183, q, 'A')); out(';; ->>HEADER<<- status: NXDOMAIN', 'e'); break; }
      const id = rnd(65535);
      if (!/axfr/i.test(s)) { const sp = 50000 + rnd(9999); udp(A, T, sp, 53, dnsMsg(id, 0x0100, dom, 'A')); udp(T, A, 53, sp, dnsMsg(id, 0x8580, dom, 'A', [rr(dom, 'A', '10.0.0.9')])); out(';; ANSWER SECTION:\n' + dom + '.\t3600 IN A 10.0.0.9'); break; }
      sess(53, [['c', tcpDns(dnsMsg(id, 0x0000, dom, 'AXFR'))], ['s', tcpDns(dnsMsg(id, 0x8400, dom, 'AXFR', ZONE.map(([n, ty, d]) => rr(n, ty, d))))]]);
      out('; <<>> DiG 9.20 <<>> axfr ' + dom + ' @10.0.0.9\n' + zoneText() + '\n;; XFR size: ' + ZONE.length + ' records'); break;
    }
    case 'nc': {
      const port = +a[a.length - 1], host = a.find(x => /^\d+\.\d+\.\d+\.\d+$/.test(x));
      if (host !== T || !BAN[port]) { out('nc: connect to ' + (host || '?') + ' port ' + (port || '?') + ' (tcp) failed: Connection refused', 'e'); break; }
      sess(port, [['s', BAN[port] + '\r\n']]); out(BAN[port]); break;
    }
    case 'snmpwalk': {
      const ci = a.indexOf('-c'), c = ci >= 0 ? a[ci + 1] : '';
      if (!a.includes(T)) { out('snmpwalk: Unknown host', 'e'); break; }
      const sp = 50000 + rnd(9999); let rid = 1000 + rnd(9000);
      udp(A, T, sp, 161, snmpMsg(0xa1, c || 'public', rid, '1.3.6.1.2.1'));
      if (c !== 'public') { out('Timeout: No Response from 10.0.0.9', 'e'); break; }
      for (const [oid, name, val] of SNMPW) { udp(T, A, 161, sp, snmpMsg(0xa2, c, rid, oid, val)); rid++; udp(A, T, sp, 161, snmpMsg(0xa1, c, rid, oid)); out(name + ' = STRING: ' + val); }
      udp(T, A, 161, sp, snmpMsg(0xa2, c, rid, '1.3.6.1.2.1.25.4.2.1.5.812', ''));
      break;
    }
    case 'mysql': {
      const ui = a.indexOf('-u'), u = ui >= 0 ? a[ui + 1] : 'root';
      if (!a.includes(T)) { out("ERROR 2002 (HY000): Can't connect to local MySQL server (use -h 10.0.0.9)", 'e'); break; }
      ask = { q: 'Enter password:', hide: 1, cb: p => {
        const ok = u === 'dbadmin' && p === 'Db#Pass2026';
        sess(3306, [['s', '5.7.42-log mysql_native_password'], ['c', 'LOGIN ' + u], ['s', ok ? 'OK' : "ERR 1045 Access denied for user '" + u + "'"]]);
        if (ok) { mode = 'sql'; db = ''; out('Welcome to the MySQL monitor.  Commands end with ;\nServer version: 5.7.42-log'); } else out("ERROR 1045 (28000): Access denied for user '" + u + "'@'10.0.0.5'", 'e');
      } }; break;
    }
    case 'curl': {
      if ((a[0] || '').startsWith('imap')) {
        const i = a.findIndex(x => x === '--user' || x === '-u'), cr = i >= 0 ? a[i + 1] || '' : '', ok = cr === 'backup:Backup2026!';
        if (!a[0].includes(T)) { out('curl: (6) Could not resolve host', 'e'); break; }
        const [user, pass = ''] = cr.split(/:(.*)/s);
        sess(143, [['s', '* OK IMAP4rev1 ready\r\n'], ['c', 'A001 LOGIN ' + user + ' ' + pass + '\r\n'], ['s', ok ? 'A001 OK LOGIN completed\r\n' : 'A001 NO [AUTHENTICATIONFAILED] Invalid credentials\r\n']].concat(ok ? [['c', 'A002 SELECT INBOX\r\n'], ['s', 'A002 OK [READ-WRITE]\r\n'], ['c', 'A003 FETCH 1 BODY[]\r\n'], ['s', '* 1 FETCH (BODY[] {120}\r\nSubject: nightly backup\r\n\r\nBackup finished. FLAG{mailboxes_hold_secrets}\r\n)\r\nA003 OK\r\n']] : []));
        if (!ok) { out('curl: (67) Login denied', 'e'); break; }
        out('From: admin@corp.local\nSubject: nightly backup\n\nBackup finished. FLAG{mailboxes_hold_secrets}\nReminder: change this mailbox password.'); break;
      }
      const m = (a.find(x => !x.startsWith('-')) || '').replace(/^https?:\/\//, '').match(/^([^/]+)(\/.*)?$/);
      if (!m || m[1] !== T) { out('curl: (6) Could not resolve host: ' + (m ? m[1] : ''), 'e'); break; }
      const p = m[2] || '/', body = WEB[p];
      sess(80, [['c', 'GET ' + p + ' HTTP/1.1\r\nHost: 10.0.0.9\r\nUser-Agent: curl/8.11.0\r\nAccept: */*\r\n\r\n'], ['s', 'HTTP/1.1 ' + (body ? '200 OK' : '404 Not Found') + '\r\nServer: nginx\r\nContent-Type: text/plain\r\nContent-Length: ' + (body || 'Not Found').length + '\r\n\r\n' + (body || 'Not Found')]]);
      out(body || '404 Not Found', body ? '' : 'e'); break;
    }
    case 'ssh': {
      const m = (a.find(x => x.includes('@')) || '').match(/^([\w.-]+)@(.+)$/);
      if (!m || m[2] !== T) { out('usage: ssh user@10.0.0.9', 'e'); break; }
      ask = { q: m[1] + '@' + T + "'s password:", hide: 1, cb: p => {
        const ok = m[1] === 'admin' && p === 'Summer2026!', junk = n => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
        sess(22, [['s', 'SSH-2.0-OpenSSH_9.6\r\n'], ['c', 'SSH-2.0-OpenSSH_9.9p1\r\n'], ['c', junk(96)], ['s', junk(96)], ['c', junk(48 + p.length)], ['s', junk(ok ? 32 : 16)]]);
        if (ok) { mode = 'ssh'; out('Welcome to Ubuntu 24.04 LTS (files01)\nLast login: from 10.0.0.12'); } else out('Permission denied, please try again.', 'e');
      } }; break;
    }
    case 'ls':
      if ((a[0] || '').startsWith('/mnt/nfs')) out(mounted ? Object.keys(NFS).join('  ') : 'ls: cannot access /mnt/nfs: No such file or directory', mounted ? '' : 'e');
      else out(Object.keys(files).join('  ') || '(no local files yet; download some with get)', Object.keys(files).length ? '' : 'd'); break;
    case 'cat': {
      const p = a[0] || '', n = p.startsWith('/mnt/nfs/') && mounted ? NFS[p.slice(9)] : files[p];
      if (n !== undefined) out(n); else out('cat: ' + p + ': No such file or directory', 'e'); break;
    }
    case 'submit': {
      const f = a.join('');
      if (!FLAGS[f]) { out('Incorrect flag. Flags look like FLAG{...}', 'e'); break; }
      if (found.has(f)) { out('Already captured.', 'd'); break; }
      found.add(f); if (found.size === TOTAL) finished = Date.now(); save(); panel();
      out('Correct! [' + FLAGS[f] + '] Flags: ' + found.size + '/' + TOTAL, 'g');
      pop(FLAGS[f]);
      brief(FLAGS[f], true);
      if (found.size === TOTAL) { out('\n  *** MISSION COMPLETE in ' + fmtTime(finished - started) + ' ***', 'win'); out('Now flip sides: type analyze to send your whole session to PacketStory and see your attack the way a defender would.\n', 'c'); setTimeout(win, 600); }
      break;
    }
    case 'hint': {
      const s = ORDER.includes(a[0]) ? a[0] : ORDER.find(x => !done(x));
      if (!s) { out('All flags captured. Nothing left to hint.', 'g'); break; }
      const h = HINTS[s]; hc[s] = Math.min((hc[s] || 0) + 1, h.length); out('[' + s + '] hint ' + hc[s] + '/' + h.length + ': ' + h[hc[s] - 1], 'd'); break;
    }
    case 'loot': out(loot.length ? 'Loot notebook:\n' + loot.map(l => '  - ' + l).join('\n') : 'Nothing written down yet. Credentials and clues are saved here as you find them.', 'd'); break;
    case 'debrief': {
      const s = ORDER.includes(a[0]) ? a[0] : null;
      if (s && !done(s)) { out('Capture the ' + s + ' flag first, then its debrief unlocks.', 'e'); break; }
      const list = s ? [s] : ORDER.filter(done);
      if (!list.length) { out('No debriefs yet. Each flag you submit unlocks one.', 'd'); break; }
      list.forEach(x => brief(x, false)); break;
    }
    case 'explain': {
      const e = EXPLAIN[a[0]];
      if (!e) { out('usage: explain <command>   (' + Object.keys(EXPLAIN).join(', ') + ')', 'e'); break; }
      out(a[0] + ': ' + e[0], 'c'); e.slice(1).filter(Boolean).forEach(l => out('  ' + l, 'd')); break;
    }
    case 'status': out('Flags: ' + found.size + '/' + TOTAL + '   packets captured: ' + P.length + '\n' + ORDER.map(s => (done(s) ? '[x] ' : '[ ] ') + s).join('\n'), 'd'); break;
    case 'capture': {
      flushFtp(); if (!P.length) { out('Nothing captured yet. Run some commands first.', 'e'); break; }
      const u = URL.createObjectURL(new Blob([pcap()], { type: 'application/vnd.tcpdump.pcap' })), l = document.createElement('a');
      l.href = u; l.download = 'my-session.pcap'; document.body.appendChild(l); l.click(); l.remove(); setTimeout(() => URL.revokeObjectURL(u), 2000);
      out('Saved my-session.pcap (' + P.length + ' packets). Open it in Wireshark, or type analyze.', 'c'); break;
    }
    case 'analyze': {
      flushFtp(); if (!P.length) { out('Nothing captured yet. Run some commands first, then analyze them.', 'e'); break; }
      const w = window.open(PCAP + '/#from-range', '_blank');
      if (!w) { out('Your browser blocked the PacketStory tab. Allow pop-ups for this site, or use capture and drop the file in manually.', 'e'); break; }
      const bytes = pcap(), n = P.length;
      const onMsg = e => {
        if (e.origin !== PCAP || e.source !== w || !e.data || e.data.type !== 'packetstory-ready') return;
        removeEventListener('message', onMsg);
        w.postMessage({ type: 'pcap', name: 'range-session.pcap', buf: bytes.buffer }, PCAP, [bytes.buffer]);
        out('Sent ' + n + ' packets to PacketStory. Switch to the new tab.', 'g');
      };
      addEventListener('message', onMsg);
      setTimeout(() => removeEventListener('message', onMsg), 30000);
      out('Opening PacketStory ...', 'd'); break;
    }
    case 'reset':
      ask = { q: 'Reset all progress and the capture? (yes/no)', cb: r => {
        if (r.toLowerCase() !== 'yes') { out('Cancelled.', 'd'); return; }
        found = new Set(); started = finished = 0; P.length = 0; files = {}; mounted = false; hc = {}; loot = []; store.set('range-loot', loot); save(); panel(); lootPanel(); t.textContent = ''; intro();
      } }; break;
    case 'clear': t.textContent = ''; break;
    case 'exit': out('You are already on your own machine. (Try clear or reset.)', 'd'); break;
    case 'sudo': out('attacker is not in the sudoers file. Root is on 10.0.0.9, not here.', 'e'); break;
    default: out(c + ': command not found. Type help.', 'e');
  }
}
function ftc(c, a) {
  const n = rc.reduce((o, k) => o[k], ft.t), f = ft.p === 'ftp', lg = (x, y) => fl.push(['c', f ? x + '\r\n' : 'SMB2 ' + x], ['s', f ? y : 'STATUS_SUCCESS']);
  switch (c) {
    case 'help': out(f ? 'commands: ls, cd <dir>, cd .., get <file>, pwd, exit' : 'commands: ls, get <file>, exit', 'd'); break;
    case 'ls': case 'dir': lg(f ? 'LIST' : 'QUERY_DIRECTORY', '150 Here comes the directory listing.\r\n226 Directory send OK.\r\n'); out(Object.entries(n).map(([k, v]) => typeof v === 'object' ? k + '/' : k).join('  ')); break;
    case 'pwd': out('"/' + rc.join('/') + '"'); break;
    case 'cd':
      if (a[0] === '..' || a[0] === '/') { a[0] === '/' ? rc = [] : rc.pop(); }
      else if (n[a[0]] && typeof n[a[0]] === 'object') rc.push(a[0]);
      else { lg('CWD ' + (a[0] || ''), '550 Failed to change directory.\r\n'); out('550 Failed to change directory.', 'e'); break; }
      lg('CWD ' + (a[0] || ''), '250 Directory successfully changed.\r\n'); break;
    case 'get':
      if (typeof n[a[0]] === 'string') { files[a[0]] = n[a[0]]; lg((f ? 'RETR ' : 'READ ') + a[0], '150 Opening BINARY mode data connection.\r\n226 Transfer complete.\r\n'); out(f ? '226 Transfer complete: ' + a[0] + ' (' + n[a[0]].length + ' bytes)' : 'getting file \\' + a[0] + ' of size ' + n[a[0]].length); }
      else out(f ? '550 Failed to open file.' : 'NT_STATUS_OBJECT_NAME_NOT_FOUND', 'e'); break;
    case 'quit': case 'exit': case 'bye': if (f) { lg('QUIT', '221 Goodbye.\r\n'); out('221 Goodbye.'); } flushFtp(); mode = 'sh'; break;
    default: out('?Invalid command. Try help.', 'e');
  }
}
function sqlh(q) {
  q = q.replace(/;\s*$/, '').trim(); const l = q.toLowerCase().replace(/\s+/g, ' ');
  if (l === 'exit' || l === 'quit' || l === '\\q') { mode = 'sh'; db = ''; out('Bye'); }
  else if (l === 'show databases') out('+--------------------+\n| Database           |\n+--------------------+\n| information_schema |\n| app                |\n+--------------------+');
  else if (l === 'use app') { db = 'app'; out('Database changed'); }
  else if (l === 'show tables') db ? out('+---------------+\n| Tables_in_app |\n+---------------+\n| secrets       |\n| users         |\n+---------------+') : out('ERROR 1046 (3D000): No database selected', 'e');
  else if (/^select \* from (app\.)?secrets$/.test(l) && (db || l.includes('app.'))) out('+----+---------+--------------------------------------+\n| id | name    | value                                |\n+----+---------+--------------------------------------+\n|  1 | api_key | k-93hd72                             |\n|  2 | flag    | FLAG{leaked_creds_open_the_database} |\n+----+---------+--------------------------------------+');
  else if (/^select \* from (app\.)?users$/.test(l) && (db || l.includes('app.'))) out('+----+----------+---------+\n| id | username | role    |\n+----+----------+---------+\n|  1 | admin    | owner   |\n|  2 | backup   | service |\n+----+----------+---------+');
  else if (!l) return;
  else out('Not supported in this lab. Try: show databases; use app; show tables; select * from secrets;', 'e');
}
function rsh(c, a) {
  if (c === 'ls') out(Object.keys(HOME).join('  '));
  else if (c === 'cat') { if (HOME[a[0]] !== undefined) out(HOME[a[0]]); else out('cat: ' + (a[0] || '') + ': No such file or directory', 'e'); }
  else if (c === 'whoami') out('admin');
  else if (c === 'id') out('uid=1000(admin) gid=1000(admin) groups=1000(admin)');
  else if (c === 'hostname') out('files01');
  else if (c === 'pwd') out('/home/admin');
  else if (c === 'sudo') out('admin is not in the sudoers file. This incident will be reported.', 'e');
  else if (c === 'exit' || c === 'logout') { mode = 'sh'; out('Connection to 10.0.0.9 closed.'); }
  else out(c + ': command not found', 'e');
}
function run(line) {
  out(pr.textContent + ' ' + (ask && ask.hide ? '' : line), 'c');
  clock += 1.5 + Math.random() * 3;
  if (ask) { const k = ask; ask = null; k.cb(line.trim()); setp(); return; }
  if (mode === 'sql') { sqlh(line); setp(); return; }
  const [c, ...a] = line.trim().split(/\s+/); if (!c) return;
  if (!started && !['help', 'hint', 'status', 'clear', 'history', 'reset'].includes(c)) { started = Date.now(); save(); }
  ({ sh, ft: ftc, ssh: rsh })[mode](c, a); setp();
}

// ---- tab completion ----
function complete(v) {
  const parts = v.split(' '), last = parts[parts.length - 1], first = parts.length === 1;
  let pool;
  if (mode === 'ft') pool = first ? ['ls', 'cd', 'get', 'pwd', 'exit', 'help'] : Object.keys(rc.reduce((o, k) => o[k], ft.t)).concat(['..']);
  else if (mode === 'ssh') pool = first ? ['ls', 'cat', 'whoami', 'id', 'exit'] : Object.keys(HOME);
  else if (mode === 'sql') pool = ['show databases;', 'use app;', 'show tables;', 'select * from secrets;', 'exit'];
  else if (first) pool = CMDS;
  else if (parts[0] === 'hint' || parts[0] === 'debrief') pool = ORDER;
  else if (parts[0] === 'explain') pool = Object.keys(EXPLAIN);
  else if (parts[0] === 'cat') pool = Object.keys(files).concat(mounted ? Object.keys(NFS).map(f => '/mnt/nfs/' + f) : []);
  else if (parts[0] === 'submit') pool = ['FLAG{'];
  else pool = [T, 'admin@' + T, '//' + T, 'corp.local', '@' + T];
  const cur = mode === 'sql' ? v : last;
  const m = pool.filter(x => x.startsWith(cur));
  if (m.length === 1) return mode === 'sql' ? m[0] : parts.slice(0, -1).concat(m[0]).join(' ') + (m[0].endsWith('{') ? '' : ' ');
  if (m.length > 1) {
    const pre = m.reduce((p, x) => { let i = 0; while (i < p.length && p[i] === x[i]) i++; return p.slice(0, i); });
    if (pre.length > cur.length) return mode === 'sql' ? pre : parts.slice(0, -1).concat(pre).join(' ');
    out(m.join('   '), 'd');
  }
  return v;
}

inp.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const v = inp.value; inp.value = '';
    if (v.trim() && !ask) { hist.push(v); if (hist.length > 200) hist.shift(); store.set('range-hist', hist); }
    hp = hist.length; run(v);
  } else if (e.key === 'ArrowUp') { e.preventDefault(); if (hp > 0) inp.value = hist[--hp]; }
  else if (e.key === 'ArrowDown') { e.preventDefault(); hp = Math.min(hist.length, hp + 1); inp.value = hist[hp] || ''; }
  else if (e.key === 'Tab') { e.preventDefault(); if (!ask) inp.value = complete(inp.value); }
  else if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); t.textContent = ''; }
  else if (e.key === 'c' && e.ctrlKey && !getSelection().toString()) { e.preventDefault(); out(pr.textContent + ' ' + inp.value + '^C', 'c'); inp.value = ''; if (ask) { ask = null; out('cancelled', 'd'); setp(); } }
});
$('#termbox').addEventListener('click', () => { if (!getSelection().toString()) inp.focus(); });
document.addEventListener('click', e => {
  const r = e.target.closest('[data-run]'), ty = e.target.closest('[data-type]');
  if (e.target.closest('[data-close]')) closeModal();
  if (r && !ask) { run(r.dataset.run); if (!r.closest('.modal')) inp.focus(); }
  if (ty) { inp.value = ty.dataset.type; inp.focus(); }
});
const fb = $('#fs'), tb = $('#termbox');
if (tb.requestFullscreen) fb.onclick = () => document.fullscreenElement ? document.exitFullscreen() : tb.requestFullscreen().then(() => inp.focus());
else fb.hidden = true;

function intro() {
  out('0vuln Range v1.0: a safe, simulated hacking lab. Everything here is fake and runs in your browser.', 'm');
  out('Target: 10.0.0.9 (files01). Capture ' + TOTAL + ' flags across 10 services and submit each with: submit FLAG{...}', 'd');
  out(found.size ? 'Welcome back. You have ' + found.size + '/' + TOTAL + ' flags. Type status to see what is left.\n' : 'New here? Start with: nmap 10.0.0.9   (stuck? type hint)\n', 'c');
}
// ---- UI: flag pop, modals, confetti ----
function pop(svc) {
  const li = [...document.querySelectorAll('#flags li')][ORDER.indexOf(svc)];
  if (li) { li.classList.add('pop'); setTimeout(() => li.classList.remove('pop'), 900); }
  window.OV && OV.toast('Flag captured: ' + svc + ' (' + found.size + '/' + TOTAL + ')');
}
let openModal = null;
function showModal(id) { closeModal(); const m = $(id); m.hidden = false; requestAnimationFrame(() => m.classList.add('open')); openModal = m; const b = m.querySelector('.btn'); if (b) b.focus(); }
function closeModal() { if (!openModal) return; const m = openModal; m.classList.remove('open'); setTimeout(() => { m.hidden = true; }, 250); openModal = null; confettiOn = false; if (matchMedia('(pointer: fine)').matches) inp.focus(); }
addEventListener('keydown', e => { if (e.key === 'Escape' && openModal) closeModal(); });
document.querySelectorAll('.modal').forEach(m => m.addEventListener('mousedown', e => { if (e.target === m) closeModal(); }));
$('#brief-open').addEventListener('click', () => showModal('#brief'));
$('#brief-go').addEventListener('click', () => { store.set('range-briefed', 1); closeModal(); });
let confettiOn = false;
function win() {
  $('#win-time').textContent = 'You owned files01 in ' + fmtTime(finished - started) + '.';
  showModal('#win');
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const cv = $('#confetti'), x = cv.getContext('2d'), W = cv.width = innerWidth, H = cv.height = innerHeight;
  const cols = ['#ff4d6d', '#9b87ff', '#22d3ee', '#34d399', '#fbbf24', '#ffffff'];
  const ps = Array.from({ length: 180 }, () => ({ x: W / 2 + (Math.random() - .5) * 200, y: H * .45, vx: (Math.random() - .5) * 16, vy: -Math.random() * 16 - 4, r: Math.random() * 6.28, vr: (Math.random() - .5) * .3, s: 4 + Math.random() * 6, c: cols[Math.random() * cols.length | 0] }));
  confettiOn = true;
  (function f() {
    x.clearRect(0, 0, W, H);
    let alive = 0;
    for (const p of ps) { p.vy += .35; p.vx *= .99; p.x += p.vx; p.y += p.vy; p.r += p.vr; if (p.y < H + 20) alive++; x.save(); x.translate(p.x, p.y); x.rotate(p.r); x.fillStyle = p.c; x.fillRect(-p.s / 2, -p.s / 4, p.s, p.s / 2); x.restore(); }
    if (alive && confettiOn) requestAnimationFrame(f); else x.clearRect(0, 0, W, H);
  })();
}
if (window.OV) OV.register('Range', [
  { t: 'Get a hint', i: 'bolt', c: '#ff4d6d', run: () => run('hint') },
  { t: 'Show status', i: 'range', c: '#ff4d6d', run: () => run('status') },
  { t: 'Download my session (.pcap)', i: 'file', c: '#ff4d6d', run: () => run('capture') },
  { t: 'Analyze my attack in PacketStory', i: 'pcap', c: '#22d3ee', run: () => run('analyze') },
  { t: 'Mission briefing', i: 'file', c: '#ff4d6d', run: () => showModal('#brief') },
]);

function brief(s, short) {
  const d = DEBRIEF[s]; if (!d) return;
  out('  ── debrief: ' + d.title + ' (' + s + ') ──', 'm');
  out('  What was wrong   ' + d.vuln, 'd');
  out('  How to fix it    ' + d.fix, 'd');
  out('  Defender sees    ' + d.seen, 'd');
  out('  ATT&CK           ' + d.attack + (short ? '      (type debrief to read them all again)' : ''), 'd');
}

intro(); panel(); lootPanel(); setp();
if (!store.get('range-briefed', 0) && !found.size) showModal('#brief');
else if (matchMedia('(pointer: fine)').matches) inp.focus();
