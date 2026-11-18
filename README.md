# A3-PS007-TC042
Privacy-Aware IPv6 IoT Security Monitoring Across Address Rotation  
Maps traffic based on port via OpenvSwitch to session ids

## Team Members
Nishant Majumdar  
Sayan Ghosh  
Dr Avijit Mondal

# YouTube Video link

https://www.youtube.com/watch?v=EdSLA-Ccn4k - Team Introduction  
https://www.youtube.com/watch?v=1-zt2yrMSWA - Demo Video and Project Overview

---

## 1. Project Overview & Architectural Highlights

Modern Internet of Things (IoT) devices in IPv6 subnets utilize **RFC 8981 (Privacy Extensions for SLAAC)** to prevent tracking by third-party observers. Endpoints periodically randomize their interface identifiers (IIDs) and rotate their global unicast IPv6 addresses (e.g. every 60 seconds).

In traditional Network Intrusion Detection Systems (NIDS), operators track rotating addresses by binding them back to Layer 2 Ethernet MAC addresses (`Ether.src`). However, in zero-trust, privacy-preserving, or multi-tenant subnets, **hardware MAC fingerprinting is strictly forbidden** due to surveillance risks, device profiling, and regulatory mandates. Furthermore, malicious nodes exploit RFC 8981 address rotation by generating **rotating-source Neighbor Discovery Protocol (NDP) floods**, blinding conventional per-IP rate limiters.

### The PS-007 Solution:
1. **Zero Hardware MAC Fingerprinting:** All Layer 2 Ethernet source addresses are stripped and dropped immediately upon ingress. No MAC address is ever recorded in RAM, persisted to disk, or broadcast in telemetry.
2. **Deterministic Link-Anchor Attribution:** OpenFlow 1.3 pushes an 802.1Q VLAN tag (`4100 + in_port`) on mirrored packets. The monitor derives a local session anchor (`SES-PORTxx`) directly from physical switch topology.
3. **Epoch-Keyed Ephemeral Pseudonyms:** Anchors map to short-lived, un-linkable 8-character pseudonyms:
   $$P = \text{HMAC-SHA256}(K_{\text{epoch}}, \; \text{tenant} \parallel \text{session})[0:8]$$
   *(Implemented as `P = HMAC(K_epoch, tenant || session_id)[:8]`)*
   When epochs rotate (every 300s), old keys are actively overwritten with zeroes in RAM for forward secrecy.
4. **Passive RFC 4862 DAD Tracking (Primary Mode A):** IoT clients remain 100% black boxes running standard Linux kernel networking. Rotations are captured passively via Duplicate Address Detection Neighbor Solicitations with strict rate bounding.
5. **Multi-Layer Protocol Anomaly Detection:** Replaces flawed Median Absolute Deviation (MAD) heuristics with RFC 4861 token buckets, $n$-of-$m$ hysteresis, CUSUM drift detection, target cardinality scanning, and RFC 6105 RA-Guard.
6. **Active SDN Defense & Port Auto-Quarantine:** When an attacker is proven (Rogue RA injection or rotating NDP flood), the monitor triggers OpenFlow 1.3 mitigation on switch `s1` (`table=0,priority=65000,in_port={port},actions=drop`), immediately severing the offending port from the network at wire speed.
7. **Integrated Web SOC Dashboard:** Clean monitoring web dashboard running on Flask, packaged directly into `monitor.py` on `http://localhost:5000` with dedicated pages for client tracking, 2D topology mapping, attack logs, live stream console, and IP rotation chains.

For complete architectural specifications, module descriptions, and formal security guarantees, see [`src/README.md`](src/README.md).  
For the complete mathematical formulations, empirical benchmark sweeps, and defense comparison matrices, see [`src/Data and Testing.md`](src/Data%20and%20Testing.md).

---

## 2. Physical Network Topology

```mermaid
flowchart TD
    subgraph LAN ["One IPv6 Subnet: fd00:abcd::/64"]
        R1["Gateway Router (r1)<br>fd00:abcd::1 (radvd)"]
        S1["Open vSwitch (s1)<br>OpenFlow 1.3 Port Tagging"]
        M1["Security Monitor (m1)<br>fd00:abcd::2 (Promiscuous Sniffer)"]
        
        H1["IoT Client h1<br>(RFC 8981 60s Rotation)"]
        H2["IoT Client h2<br>(RFC 8981 60s Rotation)"]
        H3["IoT Client h3<br>(RFC 8981 60s Rotation)"]
        H4["IoT Client h4<br>(RFC 8981 60s Rotation)"]
        H5["IoT Client h5<br>(RFC 8981 60s Rotation)"]
    end

    R1 <-->|"Port 1 (wire: 5)"| S1
    S1 -->|"Port 2: Mirrored Copy (VLAN 4100 + in_port)"| M1
    H1 <-->|"Port 3 (wire: 7)"| S1
    H2 <-->|"Port 4 (wire: 8)"| S1
    H3 <-->|"Port 5 (wire: 9)"| S1
    H4 <-->|"Port 6 (wire: 10)"| S1
    H5 <-->|"Port 7 (wire: 11)"| S1

    style LAN fill:#0b1329,stroke:#38bdf8,stroke-width:2px,stroke-dasharray: 5 5,color:#38bdf8

    classDef router fill:#7c2d12,stroke:#fb923c,stroke-width:2px,color:#ffffff;
    classDef switch fill:#1e3a8a,stroke:#38bdf8,stroke-width:3px,color:#ffffff;
    classDef monitor fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#ffffff;
    classDef client fill:#1e293b,stroke:#a78bfa,stroke-width:2px,color:#ffffff;

    class R1 router;
    class S1 switch;
    class M1 monitor;
    class H1,H2,H3,H4,H5 client;
```

---

## 3. Micro-VLAN & Wireless LAN (WLAN) IoT Architecture

In production enterprise, industrial (IIoT), smart-building, and healthcare environments, **over 90% of IoT edge devices connect wirelessly** over Wi-Fi (IEEE 802.11b/g/n/ac/ax/ah HaLow) or wireless mesh protocols (Thread, Zigbee, and Matter via 6LoWPAN border routers). 

While wired Ethernet switches provide a physical 1-to-1 port anchor (`in_port`), wireless networks introduce two critical architectural challenges:
1. **Shared Broadcast Medium & Peer-to-Peer Attack Surface:** In a traditional flat WLAN (shared SSID/BSS), all wireless stations share the same Layer 2 broadcast domain. A compromised sensor can transmit rogue Router Advertisements (RFC 6105) or spoof Neighbor Advertisements directly over the air to neighboring peer devices.
2. **Loss of Physical Port Anchoring:** Multiple wireless IoT devices connect through the same physical Access Point (AP) radio and uplink port, making physical switch port attribution insufficient on its own.
3. **MAC Randomization Conflict:** Modern wireless IoT devices frequently randomize their Wi-Fi MAC addresses. Since PS-007 strictly enforces **Zero Hardware MAC Fingerprinting** (dropping `Ether.src` at ingress), traditional MAC-based client tracking is fundamentally disallowed.

To solve this, PS-007 incorporates **Micro-VLAN (Micro-Segmentation / Per-Station PVLAN)** technology for wireless environments.

```mermaid
flowchart TD
    subgraph Wireless ["Wireless IoT Air Interface (IEEE 802.11 / WPA3)"]
        W1["Wireless IoT Sensor 1<br>(Micro-VLAN 201)"]
        W2["Wireless IoT Sensor 2<br>(Micro-VLAN 202)"]
        WA["Attacker IoT Device<br>(Micro-VLAN 203)"]
    end

    subgraph AP ["Enterprise Access Point / Border Router"]
        Isolation["L2 Station Isolation Engine<br>(Peer-to-Peer Traffic Blocked)"]
        VlanTag["802.1Q Tagging Engine<br>(Dynamic MPSK / 802.1X / RADIUS)"]
    end

    subgraph Wired ["Open vSwitch SDN Datapath (s1)"]
        OVS["OpenFlow 1.3 Datapath<br>Table 0: Flow Prioritization"]
        Mirror["SPAN Mirror Port 2<br>(Preserves 802.1Q Micro-VLAN)"]
    end

    subgraph Monitor ["PS-007 Security Monitor (m1)"]
        Ingress["Zero-MAC Ingress: Drop Ether.src"]
        Anchor["Extract Micro-VLAN Session Anchor<br>SES-VLAN0201, SES-VLAN0202, SES-VLAN0203"]
        Pseudo["Derive Ephemeral Pseudonym P<br>HMAC-SHA256(K_epoch, tenant || SES-VLAN)[:8]"]
        Detect["Real-Time Anomaly Detectors & SDN Mitigation"]
    end

    W1 -->|"802.11 Frame"| Isolation
    W2 -->|"802.11 Frame"| Isolation
    WA -->|"802.11 Frame"| Isolation

    Isolation --> VlanTag
    VlanTag -->|"802.1Q Tagged Trunk"| OVS
    OVS --> Mirror
    Mirror --> Ingress
    Ingress --> Anchor
    Anchor --> Pseudo
    Pseudo --> Detect

    Detect -.->|"Active Auto-Quarantine:<br>dl_vlan=203 actions=drop"| OVS

    classDef client fill:#1e293b,stroke:#a78bfa,stroke-width:2px,color:#ffffff;
    classDef ap fill:#7c2d12,stroke:#fb923c,stroke-width:2px,color:#ffffff;
    classDef ovs fill:#1e3a8a,stroke:#38bdf8,stroke-width:2px,color:#ffffff;
    classDef monitor fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#ffffff;

    class W1,W2,WA client;
    class Isolation,VlanTag ap;
    class OVS,Mirror ovs;
    class Ingress,Anchor,Pseudo,Detect monitor;
```

---

### 3.1 Micro-VLAN Mechanism in Wireless Networks

Micro-VLANs extend the principle of Private VLANs (PVLANs) and station isolation down to individual wireless endpoints:

1. **Layer 2 Station Isolation (Client Isolation):**
   The wireless Access Point disables peer-to-peer forwarding on the BSS. Wireless stations cannot communicate directly over radio frequencies; all traffic is forced upstream into the wired distribution switch.
2. **Dynamic Per-Station VLAN Steering:**
   During Wi-Fi association and authentication, the AP/WLC assigns each wireless IoT client a unique 802.1Q Micro-VLAN identifier. This is achieved via:
   * **802.1X / RADIUS Dynamic VLANs (RFC 3580):** Authenticated via EAP-TLS using unique device certificates.
   * **Multi-Pre-Shared Key / Identity PSK (MPSK / iPSK):** Headless IoT devices (which lack 802.1X supplicants) connect using individual pre-shared keys. The AP maps each unique PSK directly to a dedicated Micro-VLAN without requiring client-side agents.
   * **WPA3-Enterprise & 6LoWPAN Border Routers:** Assigns unique virtual interface IDs (VIFs) mapped to distinct VLAN tags for Thread/Matter networks.
3. **Wire-Format 802.1Q Tagging:**
   The AP encapsulates each station's traffic with its designated 802.1Q Micro-VLAN tag before pushing it across the wired Ethernet trunk to Open vSwitch (`s1`).

---

### 3.2 PS-007 Session Anchoring in WLAN Environments

In a Micro-VLAN wireless architecture, PS-007 functions seamlessly without requiring any code modifications:

1. **Logical Anchor Extraction:**
   When packets arrive at the monitor from the mirrored trunk port, the Attribution Engine reads the 802.1Q tag. In WLAN deployments, the tag corresponds to the station's Micro-VLAN ID rather than a physical switch port:

   $$
   \text{Session Anchor} = \text{SES-VLAN} \parallel \text{pad}_4(\mathrm{VID})
   $$

2. **Zero Hardware MAC Ingress:**
   The monitor immediately strips and drops `Ether.src`. Even if a wireless IoT sensor randomizes its Wi-Fi MAC address across associations, its authenticated Micro-VLAN binding maintains unbroken session continuity.
3. **Ephemeral Pseudonym Derivation:**
   The invariant session anchor maps to an ephemeral pseudonym $`P`$:

   $$
   P = \text{HMAC-SHA256}\Big(K_{\text{epoch}}, \; \text{tenant} \parallel \text{SES-VLAN}\Big)\Big|_{0..7}
   $$

4. **Passive RFC 4862 DAD Tracking:**
   As the wireless device rotates its temporary RFC 8981 IPv6 addresses over the air, Duplicate Address Detection Neighbor Solicitations (DAD NS) are captured and bound to the same pseudonym $`P`$.

---

### 3.3 Surgical Wireless Auto-Quarantine (Zero Collateral Damage)

In a conventional flat wireless network, mitigating an attacker requires disabling the entire SSID or blacklisting a MAC address (which fails instantly if the attacker randomizes their MAC).

Under the PS-007 Micro-VLAN architecture:
* When an attacker is proven (such as a rogue RA injection or rotating NDP flood from `Micro-VLAN 203`), the monitor issues an OpenFlow 1.3 flow rule matching strictly the offending Micro-VLAN:
  ```bash
  ovs-ofctl add-flow s1 "table=0,priority=65000,dl_vlan=203,actions=drop"
  ```
* **Wire-Rate Surgical Isolation:** The malicious wireless node is instantly dropped at line rate ($< 4\text{ ms}$) at the switch datapath.
* **Zero Collateral Damage:** Neighboring wireless IoT sensors (`Micro-VLAN 201`, `Micro-VLAN 202`) sharing the exact same physical AP radio, channel, and SSID continue operating with zero packet loss and zero degradation.
* **Administrative Remediation:** The network administrator can un-quarantine the station on demand via `/api/quarantine/release?vlan=203` or the Web SOC Dashboard.

---

### 3.4 Hardware & Vendor Compatibility Matrix

| Vendor / Platform | Wireless Micro-VLAN Technology | Attribution Anchor | Client Agent Required? |
| :--- | :--- | :---: | :---: |
| **Cisco Catalyst / Meraki** | Identity PSK (iPSK) / Dynamic RADIUS VLAN | 802.1Q Micro-VLAN | **No (Black Box)** |
| **Aruba / HPE Networking** | Multi-Pre-Shared Key (MPSK) + ClearPass | 802.1Q Micro-VLAN | **No (Black Box)** |
| **Ruckus Wireless** | Dynamic PSK (DPSK) + SmartZone | 802.1Q Micro-VLAN | **No (Black Box)** |
| **Ubiquiti UniFi** | Private Pre-Shared Keys (PPSK) | 802.1Q Micro-VLAN | **No (Black Box)** |
| **OpenWrt / Linux Hostapd** | `vlan_file` / Dynamic VLAN (`hostapd.vlan`) | 802.1Q Micro-VLAN | **No (Black Box)** |
| **Thread / 6LoWPAN** | Border Router Virtual Interface (VIF) Tagging | 802.1Q Micro-VLAN | **No (Black Box)** |

---

## 4. Quick Start Guide (One-Click Docker)

[![Docker Hub Image](https://img.shields.io/badge/Docker%20Hub-nishantmajumdar%2Fps007--ipv6--monitor-blue?logo=docker)](https://hub.docker.com/r/nishantmajumdar/ps007-ipv6-monitor)

The complete SDN emulation, Open vSwitch daemon, zero-MAC sniffer engine, and Web SOC Dashboard are published on Docker Hub:  
👉 **Docker Repository:** [hub.docker.com/r/nishantmajumdar/ps007-ipv6-monitor](https://hub.docker.com/r/nishantmajumdar/ps007-ipv6-monitor)

### Host Prerequisite (Required for XTerm GUI Windows)
The host system must have the `xhost` utility installed so Docker can display GUI XTerm windows on your desktop. If `xhost` is not installed, the first command will fail and XTerm windows inside Mininet will not open:

- **Ubuntu / Debian:**
  ```bash
  sudo apt update
  sudo apt install -y x11-xserver-utils
  ```
- **Arch Linux / CachyOS:**
  ```bash
  sudo pacman -S --needed xorg-xhost
  ```

---

### Run the Container
Execute the following commands on your host terminal:

```bash
# 1. Allow container to display GUI xterm windows on host
xhost +local:root

# 2. Run container (Docker will automatically fetch the ~84 MB image from Docker Hub)
docker run -it --privileged \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
  -v /lib/modules:/lib/modules:ro \
  -p 5000:5000 -p 8765:8765 \
  nishantmajumdar/ps007-ipv6-monitor:latest
```

**Single-line copy-paste command:**
```bash
xhost +local:root && docker run -it --privileged -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix:rw -v /lib/modules:/lib/modules:ro -p 5000:5000 -p 8765:8765 nishantmajumdar/ps007-ipv6-monitor:latest
```

*(Or if you have cloned this repository: `cd src && xhost +local:root && docker compose run --rm --service-ports ps007-monitor`)*

---

### 4.1 Evaluator Step-by-Step Guide (`mininet>` Prompt)

Once the container boots, you are at the Mininet CLI prompt (`mininet>`). Follow these simple steps:

#### Step 1: Start the Security Monitor on `m1` (Launches Web UI)
From within Mininet, open a terminal window for monitor node `m1`:
```bash
mininet> xterm m1
```
Then, inside the newly opened `m1` terminal, launch the monitor:
```bash
python3 monitor.py
```
*(Or if running headless without X11: `mininet> m1 python3 monitor.py &`)*

**Once `monitor.py` starts, open your web browser to:**
```
http://localhost:5000
```
*(Or click the clickable link printed in the `m1` terminal banner).*

---

#### Step 2: Generate Benign Traffic & Observe RFC 8981 Rotations
From within Mininet, launch shells for clients:
```bash
mininet> xterm h1 h2 h3
```
Then, inside client `h1`, ping the Gateway router:
```bash
ping -6 -c 5 fd00:abcd::1
```
*(Or directly from Mininet CLI: `mininet> h1 ping -6 -c 5 fd00:abcd::1`)*

*What happens:*
* Client `h1` emits RFC 4862 DAD Neighbor Solicitations.
* The Attribution Engine binds addresses to physical switch ports (`SES-PORT03`) and maps them to pseudonyms.
* Clients appear on the dashboard client table and 2D network map.
* **Every 60 seconds**, the Linux kernel rotates to a new temporary IPv6 address. The dashboard seamlessly records the new address in `5- ip rotation history` while preserving the authenticated session. You can inspect the client's addresses at any time:
  ```bash
  mininet> h1 ip -6 addr show dev h1-eth0
  ```

---

#### Step 3: Simulate Security Attacks & Observe Detection

##### Attack Scenario A: Rogue Router Advertisement Injection
From within Mininet, open a terminal for `h4` (or run directly from CLI):
```bash
mininet> xterm h4
# Then inside h4 terminal: python3 attacks/rogue_ra.py
```
*(Or directly from Mininet CLI: `mininet> h4 python3 attacks/rogue_ra.py`)*

* **Detection:** Captured by `RogueRADetector` (RFC 6105 RA-Guard). Port 4 is immediately flagged as `ROGUE ATTACKER` and turns **solid crimson red** on the Web SOC Map and Client Table.

##### Attack Scenario B: Rotating-Source NDP Flood & Network Sweep
From within Mininet, open a terminal for `h3` (or run directly from CLI):
```bash
mininet> xterm h3
# Then inside h3 terminal: python3 attacks/ndp_flood.py
```
*(Or directly from Mininet CLI: `mininet> h3 python3 attacks/ndp_flood.py`)*

* **Detection:** The attacker randomizes their source IPv6 address every 2 seconds to evade per-IP rate limiters. Because all packets arrive from physical Port 3, the monitor maps every rotating IP to the **same pseudonym $P$**, exhausting token buckets and triggering `NDP_RATE_ABUSE_HYSTERESIS` and `NDP_SCAN_CARDINALITY_ALERT`.
*(Or with scanning mode: `mininet> h3 python3 attacks/ndp_flood.py -t NS -r 15.0 --rotate-sec 2.0 --scan`)*

---

## 5. More Information

For exhaustive technical documentation, consult [`src/README.md`](src/README.md):
- 7-Layer Deep Technology Stack
- Ingress Zero-MAC & Security Attribution Pipeline Diagram
- Forward Secrecy & Key Ratchet Proofs
- REST API Reference (`/api/state`, `/api/history`, `/api/stream`, `/api/privacy_audit`)
- Optional Mode B (Active Cryptographic Hash Ratchet over UDP port 9000)
