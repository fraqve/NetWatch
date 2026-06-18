# NetWatch

A command-line tool I'm building in Python to analyze network traffic from `.pcap` files and flag suspicious behavior. Built entirely with Scapy — no Wireshark, no pre-made analysis libraries. I wanted to actually understand packets at the byte level instead of clicking through a GUI.

## Why I'm building this

This is my follow-up project to [Aegis-Scan](#). Aegis-Scan was about orchestrating existing tools (nmap, gobuster, nikto). NetWatch is about going one level deeper — actually reading and interpreting raw network traffic myself, instead of relying on other tools to do it for me. I'm working toward a SOC analyst role, and network traffic analysis was a gap I knew I needed to close.

## How it's organized

Instead of organizing data by protocol, I organize it by IP address. Every IP that shows up in the capture gets its own profile that builds up evidence as different protocols get analyzed. I picked this approach because I realized tracking separate lists per protocol gets messy fast — having one "file" per IP made way more sense once I thought about how I'd actually use this data later.

The plan for the full tool is three stages:

1. **Gather data** — parse the pcap and pull out structured info per IP across multiple protocols
2. **Judge the data** — decide which IPs actually look suspicious, and why
3. **Enrich it** — check suspicious IPs against VirusTotal and AbuseIPDB for real context

## What's actually working right now

The data gathering part (`analyzer.py`) is done and tested against real pcap files.

- **IP-level tracking** — every IP gets a profile: how many packets it sent, how many unique hosts it talked to. This function also creates the IP's profile the first time it shows up, so every other protocol function can assume the profile already exists.
- **ICMP** — tracks ping sweep behavior (one IP pinging a bunch of different hosts), ICMP redirects (possible man-in-the-middle), and destination unreachable floods (possible scanning).
- **TCP** — tracks unique ports an IP sends SYN packets to. High port count = possible port scan.
- **UDP** — same idea as TCP but without flags, since UDP doesn't have a handshake.
- **DNS tunneling** — flags DNS queries that are abnormally long, since that's a common way to sneak data out through a protocol that's almost never blocked by firewalls.

Every protocol function follows the same pattern: take the shared data dictionary in, update it, return it. Made it way easier to build each new one once I had the pattern down — ICMP took me an entire afternoon to figure out, TCP took like 20 minutes.

## What's not built yet

- Deciding what actually counts as "suspicious enough to flag" — like, how many ports scanned is too many? I haven't built that logic yet.
- Turning the raw data into an actual readable report
- VirusTotal enrichment for flagged IPs
- AbuseIPDB enrichment for flagged IPs

## Stuff I left out on purpose (and stuff I just can't do yet)

Being honest about both kinds here:

- **No handshake tracking.** Detecting a "real" SYN scan means checking if a SYN ever got a SYN-ACK back, which means tracking conversations across multiple packets over time. That's stateful analysis and it's above where my Python is at right now. So instead I detect scans by volume — if one IP hits a ton of unique ports, that's the signal I use.
- **DNS tunneling detection is basic.** I only catch single DNS queries that are abnormally long. A smarter attacker could split their data across a bunch of smaller queries to stay under my length threshold, and I wouldn't catch that. Catching that pattern would mean tracking query frequency over time, which is the same stateful problem as above.
- **Fragmented packets aren't fully handled.** Some fragmented packets lose their protocol headers when Scapy parses them, so I can't always tell what protocol they originally belonged to. I scoped this out instead of trying to reassemble fragment streams.
- **One architectural shortcut I'm not proud of but made on purpose:** the IP-tracking function also initializes the default values for ICMP, TCP, UDP, and DNS keys, just to avoid key errors later. That means the IP function technically "knows about" every other protocol, which isn't great separation of concerns. I didn't have a cleaner solution for this at the time without overengineering something I don't have the Python skills for yet (like a proper plugin-style registration system). It works, but it's something I'd want to redo in a v2.

## Tech stack

- Python 3
- Scapy

## A note on how I built this

I wrote every line of this myself. I used AI as a mentor to ask me questions and push back on my decisions, not to write code for me. If you ask me about any line in here, I can explain why it's there.
