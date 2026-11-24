'use strict';
// =====================================================================
// Range learning content: debriefs, command explanations, loot patterns.
// Pure data, loaded before range.js. Edit freely.
// =====================================================================

// After each flag: what was wrong, how to fix it, what a defender would see.
const DEBRIEF = {
  ftp: {
    title: 'Anonymous FTP',
    vuln: 'The FTP server accepts the user "anonymous" with any password, and a backup folder with credentials is readable by everyone.',
    fix: 'Disable anonymous logins (vsftpd: anonymous_enable=NO), never keep passwords in files, and replace FTP with SFTP.',
    seen: 'FTP is cleartext: the USER and PASS commands are readable in the capture. PacketStory flags "Cleartext FTP login".',
    attack: 'T1078.001 Default Accounts'
  },
  http: {
    title: 'robots.txt disclosure',
    vuln: 'robots.txt asks search engines not to index /secret.txt, which tells an attacker exactly where to look.',
    fix: 'robots.txt is not access control. Remove sensitive files from the web root or put them behind authentication.',
    seen: 'In the web logs: GET /robots.txt immediately followed by GET /secret.txt from the same client.',
    attack: 'T1594 Search Victim-Owned Websites'
  },
  smb: {
    title: 'SMB null session',
    vuln: 'Shares can be listed and the "public" share opened without any username or password (a null session).',
    fix: 'Disable guest and anonymous access (Samba: "restrict anonymous = 2", "map to guest = never"), require SMB signing, audit share contents.',
    seen: 'A tree connect to IPC$ and then to a share with no authentication, from a host that never logs in normally.',
    attack: 'T1135 Network Share Discovery'
  },
  nfs: {
    title: 'NFS export to everyone',
    vuln: 'The export /srv/nfs/backups is shared with "*", so any machine on the network can mount and read it.',
    fix: 'Export only to specific hosts, read-only with root_squash, e.g. "/srv/nfs/backups 10.0.0.20(ro,root_squash)". Prefer NFSv4 with Kerberos.',
    seen: 'portmapper and mount requests (ports 111 and 2049) from an unexpected client.',
    attack: 'T1039 Data from Network Shared Drive'
  },
  dns: {
    title: 'DNS zone transfer',
    vuln: 'The DNS server hands its whole zone (every hostname, including internal ones like vpn and dev-internal) to anyone who asks.',
    fix: 'Allow transfers only to your secondary servers (BIND: allow-transfer { 10.0.0.10; };), ideally signed with TSIG.',
    seen: 'An AXFR query over TCP port 53 from a client that is not a DNS server. PacketStory flags "DNS zone transfer".',
    attack: 'T1590.002 Gather Victim Network Information: DNS'
  },
  smtp: {
    title: 'Talkative banner',
    vuln: 'The mail server announces its hostname, software and (here) a secret in the greeting banner, before any login.',
    fix: 'Use a generic banner (Postfix: smtpd_banner = $myhostname ESMTP) and never put versions or internal details in it.',
    seen: 'A TCP connection to port 25 that reads the banner and closes without sending any mail: classic banner grabbing.',
    attack: 'T1592.002 Gather Victim Host Information: Software'
  },
  snmp: {
    title: 'Default SNMP community',
    vuln: 'SNMP answers to the default community string "public", and the process list leaks a database password passed on a command line.',
    fix: 'Use SNMPv3 with authentication and encryption, change or remove default communities, restrict SNMP by IP, and never pass passwords as command arguments.',
    seen: 'SNMP requests with community "public" walking the whole tree. PacketStory flags "SNMP default community".',
    attack: 'T1602.001 Data from Configuration Repository: SNMP'
  },
  mysql: {
    title: 'Leaked database credentials',
    vuln: 'MySQL is reachable from the network, and the password found in SNMP works.',
    fix: 'Bind MySQL to localhost or firewall port 3306, give each app a least-privilege account, and rotate any credential that has leaked.',
    seen: 'A successful MySQL login from a workstation that has never talked to the database before.',
    attack: 'T1078 Valid Accounts'
  },
  imap: {
    title: 'Weak mailbox over cleartext IMAP',
    vuln: 'A backup mailbox uses a password found in a file share, and IMAP sends it unencrypted.',
    fix: 'Allow only IMAPS (port 993), disable plaintext authentication, use unique passwords and MFA for mail.',
    seen: 'The IMAP LOGIN command with the username and password in cleartext. PacketStory flags "Cleartext IMAP login".',
    attack: 'T1552 Unsecured Credentials'
  },
  ssh: {
    title: 'Password reuse',
    vuln: 'The admin password from the FTP backup notes is also the SSH password.',
    fix: 'Use key-based SSH only (PasswordAuthentication no), unique passwords everywhere, and rate limiting such as fail2ban.',
    seen: 'SSH is encrypted, so the password is not visible, but a successful login from an unusual host is still a red flag in auth logs.',
    attack: 'T1021.004 Remote Services: SSH'
  }
};

// explain <command>: what it does and what it looks like on the network.
const EXPLAIN = {
  nmap: ['Port scanner. Finds which services a host runs.', 'The default -sS scan sends a SYN to each port: SYN-ACK back means open, RST means closed. -sU probes UDP ports instead.', 'On the wire: one host touching hundreds of ports in seconds. Every IDS notices it.'],
  nc: ['Netcat, the "Swiss army knife": opens a raw TCP connection and shows what the server says.', 'Many services greet you with a banner (name and version) as soon as you connect.', 'On the wire: a handshake, a banner from the server, then the connection closes.'],
  dig: ['DNS lookup tool. "dig name @server" asks one server directly.', '"dig axfr domain @server" asks for a zone transfer: the full list of records.', 'On the wire: normal lookups use UDP 53; a zone transfer uses TCP 53.'],
  ftp: ['File Transfer Protocol client.', 'Log in, then ls to list, cd to move, get to download. "anonymous" is a classic default user.', 'On the wire: everything, including the password, travels in cleartext on port 21.'],
  smbclient: ['Client for Windows file shares (SMB).', '-L lists shares, -N means "no password" (a null session). //host/share connects to one.', 'On the wire: SMB2 negotiate, then tree connects on port 445.'],
  showmount: ['Lists the NFS exports a server offers.', 'An export open to "*" can be mounted by anyone.', 'On the wire: a portmapper query on port 111, then the mount service.'],
  mount: ['Attaches a remote NFS export as a local folder.', 'After mounting, the remote files can be read with ls and cat like local files.', 'On the wire: NFS traffic on port 2049.'],
  snmpwalk: ['Reads every value an SNMP agent exposes.', '-v2c picks the protocol version, -c the community string (SNMP\'s password). "public" is the default.', 'On the wire: UDP 161; in v1/v2c the community string is visible in every packet.'],
  mysql: ['MySQL client. -h host, -u user, -p asks for the password.', 'Then: show databases; use <db>; show tables; select * from <table>;', 'On the wire: TCP 3306. Without TLS, queries and results are readable.'],
  curl: ['Makes HTTP requests from the terminal. It also speaks other protocols, like imap://.', 'curl host/path fetches a page; --user name:pass logs in.', 'On the wire: plain HTTP on port 80 shows the full request and response.'],
  ssh: ['Secure Shell: an encrypted remote login.', 'ssh user@host, then the password (or a key).', 'On the wire: after the version exchange, everything is encrypted. Only metadata is visible.'],
  submit: ['Checks a flag. Flags look like FLAG{...}.', 'Each correct flag shows a debrief: what was wrong, how to fix it, and what a defender sees.', ''],
  analyze: ['Sends your whole session to PacketStory as a .pcap.', 'Then you see your own attack from the defender\'s side.', ''],
  capture: ['Downloads your session as a .pcap file.', 'Open it in Wireshark or PacketStory.', '']
};

// Things worth writing down. Matched against normal command output (never hints).
const LOOT = [
  [/ssh user: admin\s+password: (\S+)/, m => 'admin / ' + m[1] + '  (FTP backup notes)'],
  [/Mail backup account: backup \/ (\S+)/, m => 'backup / ' + m[1] + '  (SMB it-notes)'],
  [/Internal domain: (\S+)/, m => 'domain ' + m[1]],
  [/--user dbadmin --password (\S+)/, m => 'dbadmin / ' + m[1].replace(/"$/, '') + '  (SNMP process list)'],
  [/Disallow: (\S+)/, m => 'hidden web path ' + m[1] + '  (robots.txt)'],
  [/^(\/srv\/nfs\/\S+) \*$/m, m => 'NFS export ' + m[1] + ' open to everyone'],
  [/vpn\.corp\.local\.\s+3600 IN A\s+(\S+)/, m => 'vpn.corp.local = ' + m[1] + '  (zone transfer)'],
  [/dev-internal\.corp\.local\.\s+3600 IN A\s+(\S+)/, m => 'dev-internal.corp.local = ' + m[1]],
  [/api_key \| (\S+)/, m => 'api_key ' + m[1] + '  (app database)']
];
