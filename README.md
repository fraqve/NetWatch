# ThreatProfile

A command-line tool I'm building in Python to analyze network traffic from .pcap files and flag suspicious behavior. Built entirely with Scapy — no Wireshark, no pre-made analysis libraries. I wanted to actually understand packets at the byte level instead of clicking through a GUI.

## Why I'm building this

This is my follow-up project to Aegis-Scan. Aegis-Scan was about orchestrating existing tools (nmap, gobuster, nikto). ThreatProfile is about going one level deeper — actually reading and interpreting raw network traffic myself, instead of relying on other tools to do it for me. I'm working toward a SOC analyst role, and network traffic analysis was a gap I knew I needed to close.

## How it's organized

Instead of organizing data by protocol, I organize it by IP address. Every IP that shows up in the capture gets its own profile that builds up evidence as different protocols get analyzed. I picked this approach because I realized tracking separate lists per protocol gets messy fast — having one "file" per IP made way more sense once I thought about how I'd actually use this data later.

The plan for the full tool is three stages:

- **Gather data** — parse the pcap and pull out structured info per IP across multiple protocols
- **Judge the data** — decide which IPs actually look suspicious, and why, using user-configurable thresholds
- **Enrich it** — check suspicious IPs against VirusTotal and AbuseIPDB for real context

## What's actually working right now

The data gathering part (`analyzer.py`) is done and tested against real pcap files.

- **IP-level tracking** — every IP gets a profile: how many packets it sent, how many unique hosts it talked to. This function also creates the IP's profile the first time it shows up, so every other protocol function can assume the profile already exists.
- **ICMP** — tracks ping sweep behavior (one IP pinging a bunch of different hosts), ICMP redirects (possible man-in-the-middle), and destination unreachable floods (possible scanning).
- **TCP** — tracks unique well-known ports an IP sends SYN packets to. Dynamic ports (anything above 32768) get filtered out before they ever reach this list, since those get opened and closed for one connection and aren't a real scanning signal — they're just noise.
- **UDP** — same idea as TCP but without flags, since UDP doesn't have a handshake to look for. Same port filtering applies.
- **DNS tunneling** — flags DNS queries that are abnormally long, since that's a common way to sneak data out through a protocol that's almost never blocked by firewalls.

Two things changed under the hood since the last update, neither of which show up as a new "feature" but both of which matter:

- I switched from `rdpcap` to `PcapReader`. `rdpcap` loads the entire pcap into memory before you can touch a single packet, which is fine for small test files and a disaster for anything big. `PcapReader` streams packets one at a time, so memory use stays flat no matter how large the capture is.
- Every protocol function now defends itself with `setdefault()` on the keys it needs, instead of assuming the IP-tracking function already ran and built the profile. That way the script doesn't fall over if a packet shows up without an IP layer, or in some order I didn't plan for.

Every protocol function follows the same pattern: take the shared data dictionary in, update it, return it. Made it way easier to build each new one once I had the pattern down — ICMP took me an entire afternoon to figure out, TCP took like 20 minutes.

The judgment side (`assess.py`) is in progress now:

- **ICMP assessment is written, but I haven't tested it against real data yet.** The logic: ping sweeps and unreachable floods scale in points the further they go past a free threshold, and a detected redirect instantly pushes the score past the flagging threshold on its own, since that's an active attack, not just reconnaissance. It returns the score, a flagged/not-flagged verdict, and a list of which specific behaviors contributed, so the result can actually explain itself instead of just spitting out a number.
- TCP, UDP, and DNS judgment logic isn't built yet.

## Config system

Risk thresholds and scoring multipliers used to be hardcoded numbers buried inside the assessment functions. I'm pulling all of that out into a `config.ini` file instead, so the tool's sensitivity becomes something a user can tune for their own network instead of me guessing one "correct" set of numbers that's supposed to work for everyone. Each protocol gets its own tolerance (how much normal activity is allowed before points start piling up), its own risk factor (points added per unit past that tolerance), and its own flagging threshold (how many points it takes for that protocol alone to flag the IP).

## What's not built yet

- Judgment logic for TCP, UDP, and DNS — deciding how many ports scanned or how many tunneling attempts is actually suspicious enough to flag
- Testing the ICMP assessment logic against real data
- Turning the raw data and verdicts into an actual readable report
- VirusTotal enrichment for flagged IPs
- AbuseIPDB enrichment for flagged IPs

## Known limitations (Stuff i can't do yet because it is above my skill level)

- **No stateful tracking.** Detecting a "real" SYN scan means checking if a SYN ever actually got a SYN-ACK back, which means tracking conversations across multiple packets over time. That's above where my Python is at right now, so instead I detect scans by volume — if one IP hits a ton of unique well-known ports, that's the signal I use.
- **No time-based analysis yet.** Everything in v1 is volume-based. A slow, low-and-slow scan spread out over hours would look like normal traffic to this tool right now. Time-based detection is a v2 target.
- **DNS tunneling detection is basic.** I only catch single DNS queries that are abnormally long on their own. A smarter attacker could split their data across a bunch of smaller queries to stay under my length threshold, and I wouldn't catch that. Catching that pattern means tracking query frequency over time, which is the same stateful problem as above.
- **Fragmented packets aren't handled.** Some fragmented packets lose their protocol headers when Scapy parses them, so I can't always tell what protocol they originally belonged to. I scoped this out instead of trying to reassemble fragment streams.

## Tech stack

- Python 3
- Scapy

## Where I'm at

The data gathering script (`analyzer.py`) is fully done and tested. I'm now building the judgment script (`assess.py`) that decides which IPs are actually suspicious — ICMP scoring logic is written but I still need to test it, TCP, UDP, and DNS are next on the list. In parallel I'm pulling all the scoring thresholds out of hardcoded numbers and into a user-configurable `config.ini`.
