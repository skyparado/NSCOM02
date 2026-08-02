# NSCOM02 MCO2 — Traceroute using ICMP

A custom implementation of the `traceroute` network diagnostic tool written in Python using
raw sockets and ICMP Echo Request / Echo Reply messages, with an optional IP geolocation
enhancement.

---

## 1. Files

| File | Description |
|---|---|
| `Traceroute.py` | The completed traceroute implementation (modified skeleton code). |
| `sample_output.txt` | Captured terminal output for all seven hosts, with geolocation. |
| `README.md` | This document — implementation notes, AI declaration, references. |

---

## 2. How to Run

Raw sockets require administrator privileges on Windows and root on Linux/macOS.

```
# Windows — open PowerShell or CMD as Administrator
python Traceroute.py

# Linux / macOS
sudo python3 Traceroute.py
```

The program shows a menu:

```
======================================================================
 NSCOM02 MCO2 - Traceroute using ICMP
======================================================================

 Select a host to trace:

   [1]  Google (USA)                 google.com
   [2]  DLSU Canvas (Instructure)    dlsu.instructure.com
   [3]  DLSU Website (Philippines)   dlsu.edu.ph
   [4]  CSIRO (Australia)            www.csiro.au
   [5]  M1 Limited (Singapore)       www.m1.com.sg
   [6]  NII (Japan)                  www.nii.ac.jp
   [7]  NASA (USA)                   www.nasa.gov

   [8]  Enter a host manually
   [9]  Trace the three required hosts (1-3)
  [10]  Trace all seven hosts (1-7)

======================================================================
 Choice:
 Enable IP geolocation for each hop? (y/n):
```

Options `[1]`–`[3]` are the three hosts required by the specification. Options `[4]`–`[7]`
are additional hosts in Australia, Singapore, Japan and the United States, included to
demonstrate the geolocation bonus across clearly different regions of the world. Option `[9]`
runs the three required hosts in one pass and `[10]` runs all seven. The geolocation prompt
enables the bonus feature; answering `n` prints the plain hop / RTT / IP output.

### Input validation

All three prompts validate what they receive and re-ask instead of failing:

- **Menu choice** — only `1`–`10` are accepted. Anything else prints
  `Invalid choice. Please enter one of: 1, 2, ... 10` and re-prompts.
- **Geolocation prompt** — only `y`, `yes`, `n` or `no` (case-insensitive) are accepted.
- **Manual hostname** — rejects an empty string, rejects anything containing spaces or URL
  characters (`/`, `\`, `?`, `#`) with a reminder to enter a bare hostname rather than a
  full URL, and rejects a name that does not resolve in DNS. The prompt repeats until a
  resolvable host is given.

End-of-input (Ctrl+Z / Ctrl+D) is handled at every prompt so the program exits cleanly
instead of raising `EOFError`.

### Choosing the international hosts

The extra hosts were not picked arbitrarily. Most large sites sit behind a CDN, so their
"destination" is really a local edge node — tracing `www.abc.net.au` or `www.bom.gov.au` from
the Philippines ends at an address that geolocates to **Pasig, Philippines**, which would
defeat the purpose of the demonstration. Roughly twenty candidates were tested to confirm
that the final IP genuinely resolves to the intended country *and* answers ICMP:

| Host | Destination IP | Geolocates to | Result |
|---|---|---|---|
| `www.csiro.au` | 150.229.69.37 | Melbourne, Victoria, Australia | accepted |
| `www.m1.com.sg` | 94.188.234.12 | Singapore | accepted |
| `www.nii.ac.jp` | 153.120.132.42 | Osaka, Japan | accepted |
| `www.nasa.gov` | 192.0.66.108 | San Francisco, California, USA | accepted |
| ~~`www.abc.net.au`~~ | 27.49.24.89 | Pasig, Philippines | rejected — CDN edge |
| ~~`www.ntu.edu.sg`~~ | 104.16.4.14 | Toronto, Canada | rejected — Cloudflare |
| ~~`www.nus.edu.sg`~~ | 45.60.35.225 | Paris, France | rejected — Incapsula |
| ~~`www.kyoto-u.ac.jp`~~ | 146.75.22.132 | Manila, Philippines | rejected — Fastly |
| ~~`www.mit.edu`~~ | 23.8.159.128 | Makati City, Philippines | rejected — Akamai |
| ~~`www.u-tokyo.ac.jp`~~ | 210.152.243.234 | Kitakyushu, Japan | rejected — no ICMP reply |
| ~~`www.osaka-u.ac.jp`~~ | 133.1.138.13 | Suita, Japan | rejected — no ICMP reply |

Singapore proved the hardest: almost every well-known Singaporean site is fronted by
Cloudflare, Incapsula or CloudFront and resolves to an edge node in Manila, Toronto,
Frankfurt or Paris. `www.m1.com.sg`, a Singaporean mobile operator, was one of the few whose
address is genuinely in Singapore.

The only non-standard-library dependency is `requests`, and it is needed **only** for the
geolocation bonus. The program detects whether it is installed and disables geolocation
gracefully if it is not:

```
pip install requests
```

You may also need to allow ICMP through your firewall / antivirus so that the Time Exceeded
and Echo Reply messages reach the program.

---

## 3. How It Works

Traceroute exploits the IP **Time-To-Live (TTL)** field. Every router that forwards a packet
decrements the TTL by one; when the TTL reaches zero, the router discards the packet and
sends an **ICMP Time Exceeded (Type 11)** message back to the sender. By sending ICMP Echo
Requests with TTL = 1, 2, 3, … and recording who answers each time, we discover each router
along the path in order.

| ICMP Type | Meaning | What the program does |
|---|---|---|
| `11` | Time Exceeded | An intermediate router — record its IP and RTT, then continue to the next TTL. |
| `0` | Echo Reply | The final destination answered — record it and stop the trace. |
| `3` | Destination Unreachable | Print the specific reason (from the ICMP code) and stop. |

### Program flow

1. `build_packet(ID, seq)` constructs the ICMP Echo Request: an 8-byte header
   (type, code, checksum, identifier, sequence) plus a `double` payload, with the checksum
   computed over the header and payload — identical to the packet built in MCO1.
2. `get_route(hostname)` loops `ttl` from 1 to `MAX_HOPS` (30). For each TTL it sends
   `TRIES` (3) probes, exactly like the real `tracert`.
3. Each probe creates a raw socket, sets the TTL with
   `setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))`, sends the packet, and waits on
   `select()` for up to `TIMEOUT` (2 s).
4. The reply is decoded: the ICMP header starts at offset 20 of the received packet (after
   the 20-byte IP header) and is unpacked with `struct.unpack("bbHHh", ...)` to read the
   type, code, ID and sequence.
5. The hop's IP address comes from the source address returned by `recvfrom()`, and the RTT
   is the difference between the receive time and the timestamp taken right after `sendto()`.
6. The loop terminates when an Echo Reply (Type 0) or Destination Unreachable (Type 3) is
   received, or when `MAX_HOPS` is exhausted.

### Design decisions worth noting

**Matching replies to our own probes.** A raw ICMP socket receives *every* ICMP packet
arriving at the host, not just the ones we caused. Without filtering, a stray ping reply from
another program can be misread as a hop. The program therefore verifies every packet before
accepting it:

- For **Type 0** (Echo Reply), the ID and sequence in the ICMP header are our own.
- For **Types 11 and 3**, the error message quotes back our original IP header (20 bytes)
  plus the first 8 bytes of our ICMP header. Our ID and sequence therefore sit at offset
  `48:56` of the received packet, and those are compared against what we sent.

If a packet is not ours, the program keeps waiting on the remaining time budget instead of
counting it as the hop. This is the same quoted-packet technique used for the ICMP error
handling in MCO1.

**RTT measurement.** The RTT is measured with a local timer taken immediately after
`sendto()`, rather than by reading the timestamp out of the payload. This is necessary
because a Type 11 message only quotes the first 8 bytes of our ICMP header — the `double`
timestamp we embedded is *not* included in the router's reply, so it cannot be recovered from
an intermediate hop. Using a local timer gives a correct RTT for every hop type.

**Per-probe timeout budget.** `timeLeft` is reset to `TIMEOUT` at the start of every probe.
If it were carried across hops (as a naive reading of the skeleton suggests), the budget would
be consumed by the first few hops and every later hop would falsely report a timeout.

**DNS fallback.** `dlsu.edu.ph` publishes no A record at the apex domain — only
`www.dlsu.edu.ph` resolves. Rather than aborting, `resolveHost()` retries with a `www.`
prefix and prints a note explaining the substitution.

---

## 4. BONUS — IP Geolocation

For every hop that answers with an IP address, the program queries the free
[ip-api.com](http://ip-api.com) service and displays the router's **City**, **Region**,
**Country**, and **Organization** (ISP or hosting provider).

### Implementation

The lookup lives in `getGeoInfo(ip)`:

```python
url = ("http://ip-api.com/json/" + ip +
       "?fields=status,message,country,regionName,city,isp,org,as")
response = requests.get(url, timeout=3)
info = response.json()
```

The `fields` query parameter requests only the values actually displayed, which keeps the
response small. The JSON is then formatted as `City, Region, Country | Organization`.

Four practical concerns are handled:

1. **Private addresses.** `isPrivate()` checks the RFC 1918 ranges (`10.x`, `172.16–31.x`,
   `192.168.x`), loopback (`127.x`), CGNAT (`100.64–127.x`) and link-local (`169.254.x`).
   These are LAN and ISP-internal routers with no meaningful public location, so they are
   labelled `Private / Local network` and no HTTP request is wasted on them.
2. **Rate limiting.** The free tier allows 45 requests per minute. `geoCallTimes` keeps the
   timestamps of recent calls; if 45 have been made within the last 60 seconds, the program
   sleeps until the oldest one ages out. A 30-hop trace stays well under the limit, but this
   guarantees correctness when tracing several hosts back to back.
3. **Caching.** `geoCache` stores results by IP so a repeated address (common when the same
   router answers several probes, or across multiple traces through the same ISP) is only
   ever looked up once.
4. **Graceful degradation.** A missing `requests` module, a network failure, or an
   unsuccessful API response never crashes the trace — the program falls back to a short
   explanatory message and the hop, RTT and IP are still printed.

### Sample geolocated output

Each responding hop prints its number, three RTTs and IP address on one line, with the
location and organization indented beneath it. Keeping the geolocation on its own lines means
long values such as *"Commonwealth Scientific and Industrial Research Organisation"* are
never truncated and the table never wraps in a standard terminal window.

```
  Hop       RTT 1       RTT 2       RTT 3    IP Address
----------------------------------------------------------------------
 [ 1]    1.266 ms    1.907 ms    1.994 ms    192.168.55.254
          Location : Private / Local network
 [ 3]     *           *           *          Request timed out
 [ 5]   17.716 ms   12.326 ms   20.438 ms    182.18.194.209
          Location : Cebu City, Central Visayas, Philippines
          Org      : SKYBROADBAND
 [ 8]   12.328 ms   13.968 ms   23.255 ms    161.49.13.184
          Location : Pasig, Metro Manila, Philippines
          Org      : Converge ICT Solution Inc
```

RTT values are right-aligned so the decimal points line up down each column, and `*` markers
for lost probes are centred in their column so a timed-out hop stays visually aligned with
the hops around it.

The international hosts show the feature to best effect. Tracing `www.csiro.au` makes the
whole intercontinental route visible — the traffic leaves the Philippines, crosses the
Pacific to Los Angeles, lands in Adelaide on Australia's academic network and finishes in
Melbourne, with the RTT climbing from ~27 ms to ~227 ms as it goes:

```
 [10]   26.572 ms   26.285 ms   28.657 ms    161.49.7.151
          Location : Pasig, Metro Manila, Philippines
          Org      : Converge ICT Solution Inc
 [13]  166.409 ms  168.332 ms  167.146 ms    206.72.210.64
          Location : Los Angeles, California, United States
          Org      : CoreSite
 [14]  217.320 ms  214.436 ms  214.141 ms    113.197.15.136
          Location : Adelaide, South Australia, Australia
          Org      : AARNet Pty Ltd
 [20]  226.875 ms  230.824 ms  227.610 ms    150.229.69.37
          Location : Melbourne, Victoria, Australia
          Org      : Commonwealth Scientific and Industrial Research Organisation
```

Geolocation databases should be read with some caution, however. Traces through large transit
providers often show consecutive hops reporting wildly different countries — the Singapore
trace passes through an address registered to *"Equinix Singapore"* but reported as Sydney,
and another registered to *"Arelion Sweden"* but reported as Hong Kong. This reflects how
those carriers register their address blocks rather than a real intercontinental detour on
every hop. The RTT is the more trustworthy signal: when the location jumps between continents
but the RTT stays flat, the packet has not actually moved that far.

---

## 5. Verification

The implementation was validated against the built-in Windows `tracert` utility. A trace to
`google.com` was run with `Traceroute.py`, and `tracert -d -w 2000 -h 30 64.233.189.102` was
then run against the exact IP that trace had resolved. Both produced the same hop sequence,
the same IP addresses, the same timeout positions and comparable RTTs. The custom
implementation additionally resolved hops 8 and 9, which the Windows utility reported as
timeouts on that run.

Note that this verification run is separate from the capture in `sample_output.txt`.
`google.com` is load-balanced across many addresses, so a later run resolved to
`108.177.97.139` and took a different path — this is expected behaviour, not an
inconsistency.

| Hop | `Traceroute.py` | Windows `tracert` |
|---|---|---|
| 1 | 192.168.55.254 | 192.168.55.254 |
| 2 | 192.168.0.1 | 192.168.0.1 |
| 3 | * | * |
| 4 | 172.31.64.133 | 172.31.64.133 |
| 5 | 182.18.194.209 | 182.18.194.209 |
| 6 | 182.18.194.208 | 182.18.194.208 |
| 7 | 172.31.31.12 | 172.31.31.12 |
| 8 | 161.49.13.184 | * |
| 9 | 161.49.4.41 | * |
| 10 | 161.49.6.144 | 161.49.6.144 |
| … | … | … |
| 29 | 64.233.189.102 | 64.233.189.102 |

### On the timed-out hops

Gaps in the trace (`* * *`) are normal and are not defects in the implementation. Routers may
be configured not to generate ICMP Time Exceeded messages, may rate-limit them, or may be
part of an MPLS or provider backbone that is deliberately hidden. Google's internal network
in particular does not answer for many hops, which is why the trace shows a long run of
timeouts before the destination replies. The identical gaps appear in the system `tracert`
output above.

---

## 6. Declaration of Tools and AI Use

### Tools used

- Python 3.14.6
- `requests` 2.34.2 (geolocation bonus only)
- ip-api.com free geolocation API
- Windows `tracert` (used only to independently verify the output)
- Claude Code (Claude Opus 5), used as a coding assistant

### AI use

Claude Code was used to help complete the skeleton code, debug the ICMP reply-matching logic,
and draft this documentation. The output was reviewed, executed and verified against the
system `tracert` utility before submission.

### Prompts used

> **Prompt 1 (project brief).** The complete MCO2 specification was provided verbatim,
> including the Preliminary Concepts, Project Overview, Skeleton Code, Requirements
> (Functions, Output, Reminders), Deliverables, the BONUS IP-geolocation section, and the
> full grading rubric. The instruction was to develop the traceroute application in Python
> using ICMP, complete the `#Fill in start` / `#Fill in end` sections, run the tool against
> `google.com`, `dlsu.instructure.com` and `dlsu.edu.ph`, and implement the geolocation
> enhancement.

No further prompts were required; the remaining work (testing against the three hosts,
diagnosing the `dlsu.edu.ph` DNS issue, and verifying against `tracert`) followed from that
single brief.

---

## 7. References

1. Kurose, J. F., & Ross, K. W. *Computer Networking: A Top-Down Approach* — ICMP Pinger and
   Traceroute socket programming assignments.
2. Postel, J. (1981). *RFC 792 — Internet Control Message Protocol*. IETF.
   https://www.rfc-editor.org/rfc/rfc792
3. Malkin, G. (1995). *RFC 1739 — A Primer On Internet and TCP/IP Tools*. IETF.
   https://www.rfc-editor.org/rfc/rfc1739
4. Rekhter, Y., et al. (1996). *RFC 1918 — Address Allocation for Private Internets*. IETF.
   https://www.rfc-editor.org/rfc/rfc1918
5. Python Software Foundation. *socket — Low-level networking interface*.
   https://docs.python.org/3/library/socket.html
6. Python Software Foundation. *struct — Interpret bytes as packed binary data*.
   https://docs.python.org/3/library/struct.html
7. ip-api.com. *IP Geolocation API Documentation*. https://ip-api.com/docs/api:json
