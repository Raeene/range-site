# 0vuln Range

A safe, simulated hacking lab that runs entirely in your browser. A fake target (10.0.0.9, "files01") hides three flags behind recon, an anonymous FTP server, a leaky robots.txt and reused credentials. Nothing here touches a real network: every service is simulated in JavaScript.

Type `help` to start. Commands: `nmap`, `ftp`, `curl`, `ssh`, `ls`, `cat`, `submit`, `hint`, `status`, `capture`.

## The twist: play red, then analyze blue
Everything you do generates real network packets in memory. Type `capture` to download your session as `my-session.pcap`, then drop it into [PacketStory](https://pcap.0vuln.com) to see your own attack from the defender's side: the port scan, the cleartext FTP login, the files you downloaded.

## Deploy
Static site. Cloudflare Pages: no build command, output directory `/`.

## Roadmap
More machines and levels, a web exploitation level, a scoreboard for events, a PacketStory deep link.

MIT licensed. Educational use only.
