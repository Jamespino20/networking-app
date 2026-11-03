# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

static HTML/CSS/JS (single-page, no framework, no build step)

## Users

Primary: James, university student taking Advanced Networking (CCNA/CCST curriculum). Uses it during lab prep and coursework to calculate subnets, build topologies, and generate Packet Tracer configs. Secondary (future): other students studying for CCNA/CCST certifications.

## Product Purpose

A "Swiss Army Knife" for networking coursework. Calculates FLSM/VLSM subnets, builds network topologies, delegates IPs (static/DHCP), generates routing tables (static + dynamic), tests connectivity (ping simulation), and produces IOS configurations for Packet Tracer. Success means output is trustworthy enough to paste into a graded lab, AND the tool teaches networking concepts while being used.

## Positioning

Single-file portable tool that chains the full networking workflow — Addressing Table → Topology → IP Delegation → Routing → Pinging → Services → Website (DNS) → Email (SMTP) — in one interface, with output matching Packet Tracer's exact GUI formats and IOS CLI syntax. Not a generic subnet calculator: it's an end-to-end lab companion.

## Operating Context

- Used alongside Cisco Packet Tracer during university lab sessions
- Output is pasted into Packet Tracer for graded assignments
- Runs as a local HTML file (file:// protocol), no server, no deployment
- Must work on shared university lab machines (no install permissions)
- Workflow: Addressing Table → Topology Building → IP Delegation (Static/DHCP) → Routing (Static + Dynamic simultaneously) → Pinging → Services Configuration → Website Access (DNS) → Email (SMTP)

## Capabilities and Constraints

- FLSM calculator with /31 support (Packet Tracer compatible)
- VLSM calculator with multi-network support, overlap detection, usage bars
- Topology builder: routers, interfaces, WAN links, LANs, DCE/DTE
- IP Delegation: Static vs DHCP toggle per device
- Routing engine: multi-pass propagation, static + RIPv1/RIPv2/OSPF/EIGRP
- Pinger: Realtime (Cisco-style output) + Simulation (hop-by-hop diagnosis)
- Addressing Table: works from VLSM results OR topology
- Config generation: per-router IOS commands with passwords/banner
- Services: HTTP/HTTPS, DNS (PT GUI format), Email (SMTP/POP3/IMAP)
- IPv6 subnet calculator + EUI-64 link-local
- NAT (PAT/Static/Dynamic), FHRP (HSRP/VRRP/GLBP), Security (SSH/ACLs)
- Excel workbook companion (19 sheets) exists separately
- Constraint: Excel formulas must be Excel 2016 compatible
- Constraint: IP math uses pure arithmetic (no bitwise) to avoid JS signed overflow
- Constraint: /30 for WAN links (Packet Tracer doesn't support /31 for serial)

## Evidence on Hand

- `index.html` + `styles.css` + `app.js` — the live tool
- `Networking Address Bible v2.0.xlsx` — Excel companion
- No PRODUCT.md existed before this session (no prior brand assets)

## Product Principles

1. Output must be paste-ready for Packet Tracer — correctness over decoration
2. The tool teaches while it calculates — show the reasoning, not just results
3. Workflow order matches the student's natural sequence (addressing → topology → config)
4. Portable and zero-dependency — runs from a USB drive on any machine
5. Trust is the currency — every generated config must be validated before display

## Accessibility & Inclusion

University lab environment — needs keyboard navigation, screen reader compatibility, AA contrast minimums. No specific user disability disclosed, but shared lab machines mean diverse input methods.
