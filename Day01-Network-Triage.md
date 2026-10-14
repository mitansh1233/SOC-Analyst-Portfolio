# SOC Alert Triage Report — Day 01

## 1. Executive Summary
Conducted baseline packet capture and protocol inspection on host `192.168.1.15` to audit DNS resolution, TLS session establishment, and anomalous outbound TCP SYN transmissions.

## 2. Key Technical Findings

### A. Encrypted Web Traffic & SNI Inspection (Stream 32)
- **Source:** `192.168.1.15:55483` -> **Destination:** `184.192.221.172:443` (HTTPS)
- **Handshake Verification:** Verified full TCP 3-way handshake (`[SYN]` -> `[SYN, ACK]` -> `[ACK]`) across frames 20220–21265.
- **Plaintext Domain Extraction:** Extracted Server Name Indication (`SNI=ledger.bt.co`) from Frame 21268 (`TLSv1.2 Client Hello`), confirming legitimate Brave Browser background service communication.

### B. Unanswered Outbound High-Port Connections (Stream 48)
- **Filter Applied:** `tcp.flags.syn == 1 and tcp.flags.ack == 0`
- **Source:** `192.168.1.15:55552` -> **Destination:** `45.143.30.237:18710`
- **Telemetry:** 5 outbound TCP SYN packets (330 bytes total); 0 response packets received (100% filtered ratio).
- **Additional Unanswered Targets:** Ports `35682`, `52211`, `20926`, `2067` over IPv6.

## 3. Verdict & Root Cause
**Benign / Policy Violation (P2P Application Activity):** High-port unanswered SYN packets correlate with local peer-to-peer client (`qBittorrent`) attempting to contact offline swarm peers rather than malicious C2 beaconing or internal port scanning.

## 4. Remediation / SOC Action
- In an enterprise environment, flag P2P software execution under Acceptable Use Policy (AUP) and block non-standard outbound high-port P2P traffic at the perimeter firewall.
- ## 5. Evidence Screenshots
### DNS Resolution & CNAME Inspection
![DNS Triage](Screenshot%20(139).png)

### TCP SYN Filtering
![SYN Filter](Screenshot%20(140).png)

### Full 3-Way Handshake & Plaintext SNI Extraction (Stream 32)
![Stream 32](Screenshot%20(141).png)

### TCP Conversations Matrix (100% Unanswered High-Port SYNs)
![Conversations Matrix](Screenshot%20(142).png)
