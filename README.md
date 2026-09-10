# Network Traffic Analysis & Print Stream Reassembly Tool

## Overview

This project is a Proof-of-Concept (PoC) network analysis tool written in Python. It captures, inspects, and reassembles unencrypted network printing traffic (raw TCP port 9100 / JetDirect) across a Local Area Network (LAN). 

The primary objective is to analyze the security posture of legacy print protocols, demonstrate the mechanics of Layer 2/3 traffic interception, and implement TCP payload extraction to reconstruct document streams from raw packet captures.

## Architectural Diagram

```
+-------------------+      ARP Poisoning      +-------------------+
|   Target Host     | <---------------------> |  Attacker / Host  |
|  (Client / PC)    |                         |  (Analyzer Node)  |
+---------+---------+                         +---------+---------+
          |                                             |
          |  Raw JetDirect Traffic (TCP 9100)           | Forwarded Traffic
          v                                             v
+-----------------------------------------------------------------+
|                       Target Print Device                       |
+-----------------------------------------------------------------+
```

## Key Technical Components

### 1. Frame Interception and Forwarding
* **L2 Address Spoofing:** Utilizes `scapy` to issue gratuitous ARP responses, redirecting traffic between the client and the printer through the monitoring interface.
* **IP Forwarding:** Ensures uninterrupted network flow by re-transmitting captured frames to the actual hardware MAC address, preventing service disruption during packet capture.

### 2. TCP Stream Tracking and Reassembly
* **Stream Identification:** Filters traffic matching the tuple `(Source IP, Destination IP, Destination Port 9100)`.
* **Payload Stitching:** Tracks TCP sequence numbers to reassemble out-of-order or fragmented IP segments into a continuous binary stream.

### 3. Protocol Parsing & Document Extraction
* **PJL (Printer Job Language) Stripping:** Inspects the raw stream for standard PJL header wrappers (e.g., `@PJL ENTER LANGUAGE`, `@PJL JOB`).
* **Payload Extraction:** Extracts embedded Page Description Language (PDL) payloads—such as PostScript, PCL (Printer Command Language), PWG-Raster, or raw PDF streams—and writes the reconstructed data to local storage for forensic inspection.

## Technical Requirements

* Python 3.8+
* Scapy (`pip install scapy`)
* Elevated Execution Privileges (Root / Administrator access required for raw socket opening and packet injection)
* Network Interface Card supporting promiscuous mode

## Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/almogoxt/ARP.git
cd ARP
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Security Considerations & Mitigations

This tool demonstrates the inherent vulnerabilities of legacy, unencrypted print protocols operating on internal networks.

### Vulnerability Analysis
* **Lack of Encryption:** Port 9100/AppSocket transmits raw print payloads in plaintext.
* **No Mutual Authentication:** Clients do not verify the authenticity of the print server or network route before transmitting sensitive data.

### Recommended Defenses
1. **Protocol Migration:** Enforce encrypted print protocols such as IPPS (Internet Printing Protocol Secure over HTTPS, TCP 631).
2. **Network Segmentation:** Place network printers inside isolated VLANs with strict Access Control Lists (ACLs) restricting host-to-printer access.
3. **Dynamic ARP Inspection (DAI):** Enable DAI and DHCP Snooping on enterprise switches to block unauthorized ARP response broadcasts.

## Disclaimer

This software was developed strictly for educational research, system administration, and authorized security auditing. Running packet interception or ARP redirection tools on networks without explicit permission from the network owner is illegal and unethical.
