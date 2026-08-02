# SasikiranSec — Two-Device Automatic Attack Demo

This guide runs a **real automatic detection and block** demo across two devices on the same Wi-Fi.

**What happens:**
1. **Host** runs SasikiranSec (engine + honeypot + firewall bouncer + dashboard)
2. **Remote device** runs an attack script (port scan + TCP flood)
3. **Host detects automatically** — logs → engine → ban decision → Windows Firewall → dashboard updates

No manual `block` command needed for the main demo.

---

## What You Prove

```
Remote device  --port scan + flood-->  Host honeypot (:9999)
                                              |
                                              v
                                    attack.log (syslog)
                                              |
                                              v
                                    SasikiranSec engine
                                    (leaky bucket scenario)
                                              |
                              +---------------+---------------+
                              v               v               v
                         Alert in UI    Ban decision    Prometheus :6060
                                              |
                                              v
                                    Firewall bouncer
                                              |
                                              v
                              Remote IP BLOCKED at network level
```

---

## Requirements

| Item | Host PC | Remote device |
|------|---------|---------------|
| Project folder | Yes (full repo) | No |
| Script | `scripts\run.ps1` | `run.ps1` only (from export) |
| Admin | Yes (for firewall bouncer) | No |
| Network | Same Wi-Fi as remote | Same Wi-Fi as host |

---

## Architecture

| Component | Port | Role |
|-----------|------|------|
| `sasikiransec.exe` | 8080 | Detection engine + Local API |
| Dashboard (UI) | 3000 | Live alerts and bans |
| Prometheus metrics | 6060 | Engine metrics (`/metrics`) |
| Attack honeypot | 9999 | TCP server — logs every connection to `attack.log` |
| Firewall bouncer | — | Polls API, creates Windows Firewall block rules |

**Detection scenario:** `sasikiran/net-flood` — triggers when 6+ attack events from the same IP arrive within 5 seconds (port scan + flood pattern).

---

## Part 1 — One-Time Setup (Host)

Open **PowerShell as Administrator**:

```powershell
cd C:\Users\Sasikiran\Documents\crowdsec
.\scripts\run.ps1 setup
```

This builds binaries, creates `.local/` config, installs SSH + network attack detection collections, and registers the firewall bouncer.

Wait for: `Setup complete`

---

## Part 2 — Start the Host (Keep Window Open)

```powershell
cd C:\Users\Sasikiran\Documents\crowdsec
.\scripts\run.ps1 start
```

1. Click **Yes** on UAC (Administrator)
2. **Keep this window open** for the entire demo
3. Browser opens: **http://127.0.0.1:3000**

You should see:

```
SasikiranSec RUNNING
  Dashboard:   http://127.0.0.1:3000
  Your LAN IP: 172.17.11.200
  Test port:   9999
```

Note your **LAN IP** — the remote device needs it.

Optional — verify metrics (Prometheus):

```
http://127.0.0.1:6060/metrics
```

Look for `cs_*` counters increasing as attacks are processed.

---

## Part 3 — Copy Attacker Script to Remote Device

On host (second PowerShell window):

```powershell
cd C:\Users\Sasikiran\Documents\crowdsec
.\scripts\run.ps1 export
```

This copies `run.ps1` to your **Desktop**. Send **only that file** to the remote device.

Show host LAN IP:

```powershell
.\scripts\run.ps1 info
```

---

## Part 4 — Run the Attack (Remote Device)

On the **remote device**, in the folder where `run.ps1` was saved:

```powershell
.\run.ps1 attack -HostIp 172.17.11.200
```

Replace `172.17.11.200` with the host LAN IP from Part 2.

### What the attack script does

| Phase | Action | Purpose |
|-------|--------|---------|
| **1. Port scan** | Probes ports 22, 80, 443, 3389, 8080, 9990–9999 | Simulates reconnaissance |
| **2. TCP flood** | 20 rapid connections to port 9999 | Triggers honeypot logging + detection |

### Expected output (remote)

```
===== SasikiranSec Remote ATTACK =====

  Your IP:   172.17.11.55
  Target:    172.17.11.200

  [1/2] Port scan (15 ports)...
        Port 9999 OPEN

  [2/2] TCP flood (20 connections to port 9999)...
        20/20 connections succeeded

  ATTACK COMPLETE

  On the HOST PC:
    1. Watch dashboard http://127.0.0.1:3000
    2. Run: .\scripts\run.ps1 status
    3. Firewall bouncer blocks your IP automatically
```

---

## Part 4b — Attack from Mobile Data (Different Network)

Use this when the attacker is **not on the same Wi-Fi** (e.g. phone on **4G/mobile data**).

### Why LAN IP does not work

`172.17.x.x` / `192.168.x.x` are **private** addresses. A phone on mobile data cannot reach them. You need your laptop's **public IP** and a **router port forward**.

### Host setup (one time)

1. Keep `run.ps1 start` running (Admin window open).

2. Run:

```powershell
.\scripts\run.ps1 extern
```

This shows:
- Your **public IP** (give this to the phone)
- Your **LAN IP** (for router config)
- Saves `SasikiranSec-CROSS-NETWORK.txt` and `mobile-flood.sh` to Desktop

3. On your **home router**, add port forward:

| Setting | Value |
|---------|--------|
| Protocol | TCP |
| External port | 9999 |
| Internal IP | Laptop LAN IP (from `extern`) |
| Internal port | 9999 |

### Phone attack (Android + Termux)

1. Turn **Wi-Fi OFF**, use **mobile data only**.
2. Install [Termux](https://termux.dev/), then:

```bash
pkg install netcat-openbsd
for i in $(seq 1 25); do nc -w2 YOUR_PUBLIC_IP 9999 </dev/null; done
```

Or copy `mobile-flood.sh` from Desktop:

```bash
bash mobile-flood.sh YOUR_PUBLIC_IP 9999 25
```

### PC on another network

```powershell
.\run.ps1 attack -HostIp YOUR_PUBLIC_IP
```

### What you will see

- Dashboard shows the phone's **carrier/public IP** (not a private Wi-Fi IP)
- Map pin at the mobile network location
- Ban blocks that public IP at Windows Firewall

### If port 9999 stays closed from phone

- Port forward not saved / wrong LAN IP
- ISP uses CGNAT (try phone hotspot + laptop on Wi-Fi as fallback, or use Tailscale VPN)
- Host firewall: `run.ps1 start` already opens TCP 9999 on Public profile

---

## Part 5 — Watch Automatic Detection (Host)

**Within 10–20 seconds** after the attack:

### Dashboard (http://127.0.0.1:3000)

| Panel | What appears |
|-------|----------------|
| **Active Alerts** | Count increases |
| **Alerts table** | IP + reason `sasikiran/net-flood` or **Network Port Scan / Flood** |
| **Ban Decisions** | Attacker IP with action `ban` |
| **Active Bans** | Count increases |

Refresh is automatic every 5 seconds, or click **Refresh**.

### Terminal status

```powershell
.\scripts\run.ps1 status
```

Expected:

```
--- Ban decisions ---
| 172.17.11.55 | ban | sasikiran/net-flood | 4h |

--- Firewall rules ---
    SasikiranSec-Block-172-17-11-55 -> 172.17.11.55
```

### Verify block (remote device)

Run the attack again — connections to port 9999 should **fail** because Windows Firewall now blocks that IP.

---

## Part 6 — Stop Demo

On host:

```powershell
.\scripts\run.ps1 stop
```

Or press **Ctrl+C** in the `start` window.

---

## Single-PC Demo (No Second Device)

If you only have one PC, inject simulated attack logs:

```powershell
.\scripts\run.ps1 simulate 203.0.113.99
```

Watch the dashboard — alert and ban appear automatically for that IP.

---

## Demo Checklist (Print This)

| Step | Who | Command | Expected |
|------|-----|---------|----------|
| 1 | Host | `run.ps1 setup` | Setup complete (once) |
| 2 | Host | `run.ps1 start` | RUNNING — keep window open |
| 3 | Host | Open http://127.0.0.1:3000 | Dashboard live |
| 4 | Host | `run.ps1 export` | run.ps1 on Desktop |
| 5 | Host | `run.ps1 info` | Note LAN IP |
| 6 | Remote | `run.ps1 attack -HostIp LAN_IP` | Port scan + flood completes |
| 7 | Host | Watch dashboard | Alert + ban appear |
| 8 | Host | `run.ps1 status` | Firewall rule for attacker IP |
| 9 | Remote | Run attack again | Connections FAIL (blocked) |
| 10 | Host | `run.ps1 stop` | All stopped |

---

## What to Say to the Judge (45 seconds)

> "This is SasikiranSec — a security platform that detects and blocks malicious IPs.
>
> On the host we run the detection engine, a honeypot on port 9999, and a Windows Firewall bouncer. Prometheus metrics run on port 6060 for observability.
>
> From a second device on the same Wi-Fi, we run an attack script that port-scans the host and floods TCP connections — simulating reconnaissance and a small DDoS.
>
> Each connection is logged. The engine's leaky-bucket scenario detects the flood, creates a ban, and the bouncer adds a real firewall rule. You can see the alert and ban appear live in the dashboard — no manual intervention."

---

## How Detection Works (Technical)

```
Remote TCP connect :9999
        |
        v
scripts/lib/test-server.ps1  (honeypot)
        |
        writes syslog line to .local/logs/attack.log
        e.g. "ATTACK type=flood source=172.17.11.55 port=9999"
        |
        v
Engine reads attack.log (acquis.yaml)
        |
        v
Parser: sasikiran/net-logs  ->  meta.log_type = sasikiran_net_attack
        |
        v
Scenario: sasikiran/net-flood  (6 events / 5 sec / same IP)
        |
        v
Profile: default_ip_remediation  ->  ban 4h
        |
        +--> Local API :8080  -->  Dashboard :3000
        |
        +--> Prometheus :6060  (cs_alerts, cs_buckets_*, etc.)
        |
        v
bouncer-worker.ps1  -->  Windows Firewall rule  -->  IP blocked
```

---

## All Commands

### Host PC

| Command | Purpose |
|---------|---------|
| `.\scripts\run.ps1 setup` | First-time build + detection rules |
| `.\scripts\run.ps1 start` | Start engine, honeypot, bouncer, UI |
| `.\scripts\run.ps1 info` | Show LAN IP (same Wi-Fi) |
| `.\scripts\run.ps1 extern` | Public IP + cross-network / phone setup |
| `.\scripts\run.ps1 status` | Show bans + firewall rules |
| `.\scripts\run.ps1 simulate IP` | Test without second device |
| `.\scripts\run.ps1 export` | Copy attacker script to Desktop |
| `.\scripts\run.ps1 block IP` | Manual ban (optional) |
| `.\scripts\run.ps1 stop` | Stop everything |

### Remote device (run.ps1 only)

| Command | Purpose |
|---------|---------|
| `.\run.ps1 attack -HostIp LAN_IP` | Same Wi-Fi attack |
| `.\run.ps1 attack -HostIp PUBLIC_IP` | Different network (needs port forward) |

### URLs (host)

| URL | Purpose |
|-----|---------|
| http://127.0.0.1:3000 | Dashboard |
| http://127.0.0.1:6060/metrics | Prometheus metrics |
| http://127.0.0.1:8080 | Local API (internal) |

---

## Troubleshooting

### Remote attack says "No ports open"

- Host must run `run.ps1 start` (Admin window open)
- Same Wi-Fi on both devices
- Use host **LAN IP**, not `127.0.0.1`
- Windows Firewall on host: port 9999 rule is created by `start`

### Dashboard shows no alert after attack

1. Check honeypot is running: `run.ps1 start` window open
2. Check attack log growing: `.local\logs\attack.log` should have new lines
3. Re-run setup: `.\scripts\run.ps1 setup` (installs `sasikiran/demo` collection)
4. Restart: `stop` then `start`

### Ban appears but no firewall rule

- `run.ps1 start` must run **as Administrator**
- Check bouncer: status should list firewall rule

### Wrong IP banned / block doesn't work

Remote script may show a **virtual IP** (e.g. `172.28.0.1` from Docker/WSL).

On remote device run `ipconfig` → use **Wi-Fi IPv4** (same subnet as host, e.g. `172.17.11.x`).

The honeypot logs the **actual TCP source IP** — that is what gets banned. If traffic routes through a virtual adapter, detection may not match what you expect.

### Backend offline in dashboard

Engine not running. Run `.\scripts\run.ps1 start` and keep Admin window open.

### GeoIP warnings in engine log

Safe to ignore — detection and blocking still work.

---

## Files Reference

| Path | Purpose |
|------|---------|
| `scripts/run.ps1` | Host + remote entry point |
| `scripts/lib/test-server.ps1` | Honeypot — logs attacks |
| `scripts/lib/bouncer-worker.ps1` | Firewall bouncer |
| `scripts/lib/ui-server.ps1` | Dashboard server |
| `.local/logs/attack.log` | Live attack log (engine reads this) |
| `config/demo/sasikiran-net-flood.yaml` | Detection scenario |
| `ui/index.html` | Dashboard UI |

For full project documentation see [instruction.md](instruction.md).
