# 0vuln Range

A safe, simulated hacking lab that runs entirely in your browser. One target (10.0.0.9, "files01"), **10 vulnerable services, 10 flags**: anonymous FTP, a leaky robots.txt, an SMB null session, a world-readable NFS export, a DNS zone transfer, a chatty SMTP banner, a default SNMP community, leaked MySQL credentials, a weak IMAP backup account and reused SSH credentials. Nothing touches a real network: every service is simulated in JavaScript.

Play at **[range.0vuln.com](https://range.0vuln.com)**. Type `help` to start, `hint` when stuck.

## Play red, then analyze blue
Every command generates real, well-formed packets in memory: TCP handshakes with sequence numbers, valid IPv4/TCP/UDP checksums, real DNS (including AXFR over TCP) and SNMP (BER) encodings. The capture opens cleanly in Wireshark.

- `analyze` opens [PacketStory](https://pcap.0vuln.com) in a new tab and hands it your session (`postMessage`, origin-checked on both sides). You see your own port scan, cleartext logins, zone transfer and stolen files from the defender's side.
- `capture` downloads the session as `my-session.pcap`.

## Features
- Mission panel: progress, per-service flag tracker (click a service for a hint), timer
- Tab completion, persistent history, Ctrl+L / Ctrl+C, fullscreen terminal
- Progress saved in `localStorage`; `reset` starts over

## Files
- `index.html`, `range.css`, `range.js` (no inline scripts or styles; strict CSP in `_headers`)
- `_headers` sets `Cross-Origin-Opener-Policy: same-origin-allow-popups` so the PacketStory hand-off can keep a handle to the tab it opens

## Deploy
Static site. Cloudflare Pages: no build command, output directory `/`.

## Roadmap
More machines and levels, a web exploitation level, a scoreboard for events.

MIT licensed. Educational use only.
