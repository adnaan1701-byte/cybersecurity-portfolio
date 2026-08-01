# Incident Report: NetSupport RAT Beaconing — DESKTOP-TEYQ2NR

## Scenario
SIEM alerted on repeated NetSupport Manager RAT signature hits to 45.131.214[.]85
over TCP/443, starting 2026-02-28 19:55 UTC. Pcap pulled from internal segment
10.2.28.0/24 for investigation.

## Executive Summary
Host DESKTOP-TEYQ2NR (10.2.28.88), logged in as user brolf (Becka Rolf), was
identified beaconing to a known-bad external IP consistent with NetSupport RAT
C2 activity. Traffic showed periodic HTTP POST requests to a fixed URI at
~60-second intervals, indicative of automated check-in/beaconing behavior
rather than user-driven browsing.

## Affected Host
| Field | Value |
|---|---|
| IP Address | 10.2.28.88 |
| MAC Address | 00:19:d1:b2:4d:ad |
| Hostname | DESKTOP-TEYQ2NR |
| Username | brolf |
| Full Name | Becka Rolf |
| Domain | EASYAS123.TECH |

## Indicators of Compromise
| Indicator | Type | Context |
|---|---|---|
| 45.131.214.85 | IP | C2 server, NetSupport RAT |
| /fakeurl.htm | URI | C2 check-in endpoint |

## Technical Findings
- Traffic to 45.131.214.85 was plaintext HTTP (not TLS) despite occurring over
  TCP/443, a common evasion technique to blend in with expected HTTPS traffic
  on that port.
- POST requests to /fakeurl.htm recurred at ~60 second intervals — consistent
  with automated C2 beaconing rather than manual browsing.
- Host identity was reconstructed using NBNS (hostname), Kerberos AS-REQ
  (username), and SAMR QueryUserInfo (full name) — no single protocol
  provided all identifying fields.

## MITRE ATT&CK Mapping
- T1219 – Remote Access Software (NetSupport Manager RAT)
- T1071.001 – Application Layer Protocol: Web Protocols (C2 over HTTP)

## Recommendations
- Isolate DESKTOP-TEYQ2NR from the network pending forensic imaging
- Block 45.131.214.85 at the perimeter firewall
- Reset credentials for user brolf
- Sweep environment for other hosts communicating with the same C2 IP

## Analysis Methodology / Filters Used

1. Pivoted from the known-bad IOC from the SIEM alert:
   `ip.addr == 45.131.214.85`
   → Identified infected host IP (10.2.28.88) and observed HTTP POST beaconing
     to /fakeurl.htm.

2. Retrieved MAC address from Ethernet layer of a packet sourced from the
   infected host.

3. Identified hostname via NetBIOS Name Service broadcast:
   `ip.addr == 10.2.28.88 && nbns`
   → DESKTOP-TEYQ2NR

4. Identified username via Kerberos AS-REQ (plaintext cname field):
   `ip.addr == 10.2.28.88 && kerberos.msg_type == 10`
   → brolf

5. Identified full name via SAMR QueryUserInfo response:
   `ip.addr == 10.2.28.88 && samr`
   → Becka Rolf
