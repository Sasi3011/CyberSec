# CyberSec — Project Guide & Instructions

This document explains what **CyberSec** is, what was changed in this repository, how the system works, whether it is only a demo or usable against real attacks, and how to test it step by step.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [What Was Changed in This Fork](#2-what-was-changed-in-this-fork)
3. [How It Works (Architecture)](#3-how-it-works-architecture)
4. [Demo vs Real-Life — Important Distinction](#4-demo-vs-real-life--important-distinction)
5. [Prerequisites](#5-prerequisites)
6. [Setup Instructions (Windows Local Dev)](#6-setup-instructions-windows-local-dev)
7. [Running the Platform](#7-running-the-platform)
8. [Testing — Simulated Attacks (Safe Local Demo)](#8-testing--simulated-attacks-safe-local-demo)
9. [Testing — Real Attacks (Production-Style)](#9-testing--real-attacks-production-style)
10. [Dashboards & Monitoring](#10-dashboards--monitoring)
11. [CLI Reference](#11-cli-reference)
12. [Troubleshooting](#12-troubleshooting)
13. [File & Folder Map](#13-file--folder-map)

---

## 1. What Is This Project?

**CyberSec** is a production-grade **IDS/IPS** (Intrusion Detection / Prevention System) platform for Windows local development, demos, and security testing. It:

- Reads logs and HTTP traffic (**acquisition**)
- Parses them into structured events (**parsers**)
- Applies detection rules (**scenarios** from the CyberSec Hub)
- Creates **alerts** and **ban decisions** for malicious IPs
- Shares threat intelligence via the **Central API (CAPI)** (optional)
- Lets **bouncers** (firewall, nginx, cloud WAF, etc.) enforce blocks

This fork renames the platform to **CyberSec**, builds custom binaries, and adds Windows-friendly local development scripts so you can learn and test without installing a Linux server.

| Item | Value |
|------|-------|
| Platform name | CyberSec |
| Author / branding | CyberSec |
| Security engine binary | `bin\cybersec.exe` |
| CLI binary | `bin\cybercli.exe` |
| Local dev config | `.local\cybersec-local.yaml` |
| Production config path (Windows) | `C:\ProgramData\CyberSec\` |
| Upstream base | CyberSec v1.7.8 (MIT License) |

**Bottom line:** This is **not a fake or toy security tool**. The detection engine, parsers, and scenarios are the same CyberSec technology used in production worldwide. What is "demo-like" in your current setup is only the **log source** (a sample file) and the lack of a **bouncer** to block traffic on the network.

---

## 2. What Was Changed in This Fork

### 2.1 Branding & Binaries

| Original (CyberSec) | This fork (CyberSec) |
|---------------------|--------------------------|
| `cybersec.exe` | `cybersec.exe` |
| `cscli.exe` | `cybercli.exe` |
| CyberSec | CyberSec |
| `C:\ProgramData\CyberSec\` | `C:\ProgramData\CyberSec\` |

A new package `pkg/branding/branding.go` centralizes all display names:

```go
PlatformName = "CyberSec"
CLIName      = "cybercli"
AuthorName   = "CyberSec"
ServiceName  = "CyberSec"
```

### 2.2 Source Code Modifications (16 tracked files)

| File / Area | Change |
|-------------|--------|
| `pkg/branding/branding.go` | **New** — central branding constants |
| `pkg/cwversion/version.go` | Version output shows "CyberSec by CyberSec" |
| `cmd/crowdsec-cli/main.go` | CLI renamed to `cybercli`, help text uses CyberSec |
| `cmd/crowdsec/serve.go` | Log messages use branded Central API name |
| `cmd/crowdsec/run_in_svc_windows.go` | Windows service name = CyberSec |
| `pkg/apiserver/*.go` | Local API / CAPI log messages rebranded |
| `pkg/apiclient/useragent/useragent.go` | HTTP User-Agent: `cybersec/...` instead of `cybersec/...` |
| `pkg/hubops/enable.go` | **Windows fix** — copies hub files instead of symlinks (Windows often blocks symlinks without admin) |
| `config/config_win.yaml` | Production paths point to `CyberSec` folders |
| `config/cybersec-local.yaml` | Local dev config template |
| `config/acquis_local_dev.yaml` | Reads from `.local/logs/sample.log` (no admin needed) |
| `build/mk/platform/windows.mk`, Makefiles | Build output names updated |
| `README.md` | Rewritten for CyberSec quick start |

### 2.3 New Scripts & UI (not in upstream git diff — local additions)

| Script | Purpose |
|--------|---------|
| `scripts/cybersec-build.ps1` | Build engine + CLI on Windows |
| `scripts/cybersec-setup.ps1` | Create `.local/` config, hub, DB, credentials |
| `scripts/cybersec-run.ps1` | Start engine (offline, no CAPI) |
| `scripts/cybersec-run-capi.ps1` | Start engine with CyberSec Central API |
| `scripts/cybersec-console-enroll.ps1` | Register with CyberSec Cloud Console |
| `scripts/cybersec-dev.ps1` | Engine + simple HTML dashboard on port 3000 |
| `scripts/cybersec-ui.ps1` | Simple local dashboard only |
| `scripts/run.ps1` | Unified orchestrator: setup, start, stop, dashboard, attack demo |
| `scripts/cybersec-test-alert.ps1` | Inject fake SSH brute-force lines → trigger alert |
| `ui/index.html` | Custom CyberSec dashboard (alerts + decisions) |
| `docker-compose.cybersec-ui.yml` | Docker setup for community CyberSec Web UI |

### 2.4 What Was NOT Changed

- Core detection logic (parsers, scenarios, buckets, leaky algorithms)
- CyberSec Hub compatibility (same collections, e.g. `crowdsecurity/sshd`)
- Local API protocol (bouncers and UIs still speak standard LAPI)
- SQLite database schema and alert/decision model
- Integration with CyberSec Central API and Console (optional)

---

## 3. How It Works (Architecture)

```
┌─────────────────┐     ┌──────────────┐     ┌───────────┐     ┌────────────┐
│  Log sources    │────▶│  Acquisition │────▶│  Parsers  │────▶│  Scenarios │
│  (files, syslog,│     │  (acquis.yaml)│     │  (hub)    │     │  (hub)     │
│   journald, etc)│     └──────────────┘     └───────────┘     └─────┬──────┘
└─────────────────┘                                                  │
                                                                     ▼
┌─────────────────┐     ┌──────────────┐     ┌───────────┐     ┌────────────┐
│  Bouncers       │◀────│  Local API   │◀────│  Profiles │◀────│  Alerts    │
│  (firewall,     │     │  :8080       │     │  (ban 4h) │     │  Decisions │
│   nginx, etc.)  │     └──────────────┘     └───────────┘     └────────────┘
└─────────────────┘            │
                               ▼ (optional)
                    ┌──────────────────────┐
                    │ CyberSec Central API │
                    │ CyberSec Cloud Console     │
                    └──────────────────────┘
```

### Pipeline steps (example: SSH brute force)

1. **Acquisition** — Engine tails `.local/logs/sample.log` (or real `/var/log/auth.log` on Linux).
2. **Parser** — `crowdsecurity/syslog-logs` → `crowdsecurity/sshd-logs` extract fields: source IP, user, log type `ssh_failed-auth`.
3. **Scenario** — `crowdsecurity/ssh-bf` uses a **leaky bucket**: 5 failed auth events from the same IP within ~10 seconds → **alert**.
4. **Profile** — `default_ip_remediation` creates a **ban decision** for 4 hours on that IP.
5. **Local API** — Decisions stored in SQLite; bouncers poll `GET /v1/decisions`.
6. **Bouncer** (if installed) — Adds firewall rule / nginx deny / cloud WAF block.

### SSH brute-force scenario (installed by setup)

From `.local/config/hub/scenarios/crowdsecurity/ssh-bf.yaml`:

- **Trigger:** 5+ `ssh_failed-auth` events from same source IP
- **Leak speed:** 10 seconds
- **Result:** Alert labeled `SSH Bruteforce`, remediation enabled
- **Decision:** IP ban for 4 hours (via `profiles.yaml`)

---

## 4. Demo vs Real-Life — Important Distinction

| Aspect | Your current local setup | Real production deployment |
|--------|--------------------------|----------------------------|
| Log source | `.local/logs/sample.log` (fake lines) | Real server logs (SSH, IIS, nginx, Windows Event Log) |
| Detection engine | **Real** CyberSec logic | **Same** engine |
| Hub scenarios | **Real** rules from CyberSec Hub | **Same** rules (+ more collections) |
| Alerts / decisions | **Real** — stored in DB, visible in UI | **Same** |
| IP blocking on network | **No** — no bouncer installed | **Yes** — firewall/nginx/cloud bouncer |
| Threat intel sharing | Disabled (`-no-capi`) by default | Optional CAPI to CyberSec Cloud Console |
| Admin rights | Not required for file-based acquis | May need admin for firewall bouncer / symlinks |

### Is it "only a demo"?

**Partially:**

- **Demo part:** Reading a hand-written `sample.log` and viewing alerts in a local dashboard is a **safe learning demo**. No attacker and no real server is involved.
- **Real part:** The engine, parsers, scenarios, alert generation, and ban decisions are **identical to production CyberSec**. If you point acquisition at real logs and attach a bouncer, it **will detect and block real attacks**.

### What makes it "real" in production?

1. **Real log acquisition** — Monitor actual SSH, web server, or application logs.
2. **Bouncer** — Install [CyberSec bouncers](CyberSec documentation) (firewall, nginx, Windows firewall, etc.) so ban decisions become actual blocks.
3. **More collections** — Install Hub collections for nginx, IIS, SQL injection, CVE exploits, etc.
4. **CAPI (optional)** — Share/receive community blocklists via CyberSec Console.

---

## 5. Prerequisites

- **Windows 10/11** (your current environment)
- **Git** — to clone/update the repo
- **Go 1.26+** — installed automatically by `cybersec-build.ps1` via winget if missing
- **Internet** — for Hub update during setup (download detection rules)
- **Optional:** Docker — for CyberSec Web UI on port 3001
- **Optional:** Node.js + pnpm — alternative to Docker for CyberSec Web UI

---

## 6. Setup Instructions (Windows Local Dev)

Open **PowerShell** in the repository root (`c:\Users\CyberSec\Documents\crowdsec`).

### Step 1 — Build binaries

```powershell
.\scripts\cybersec-build.ps1
```

**Output:**
- `bin\cybersec.exe` — security engine
- `bin\cybercli.exe` — command-line interface

### Step 2 — Initialize local environment

```powershell
.\scripts\cybersec-setup.ps1
```

**This creates:**

```
.local/
├── cybersec-local.yaml      # Main config
├── config/
│   ├── acquis.yaml           # Points to sample.log
│   ├── hub/                  # Downloaded detection rules
│   ├── profiles.yaml         # Ban policies
│   ├── simulation.yaml       # simulation: false (real bans)
│   └── local_api_credentials.yaml
├── data/
│   └── cybersec.db       # SQLite database
└── logs/
    └── sample.log            # Initial fake SSH attack lines
```

**Installed Hub items:**
- Collection: `crowdsecurity/sshd`
- Parser: `crowdsecurity/syslog-logs`

### Step 3 — Verify installation

```powershell
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml version
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml hub list
```

---

## 7. Running the Platform

### Option A — Engine only (recommended first)

```powershell
.\scripts\cybersec-run.ps1
```

- Local API: `http://127.0.0.1:8080`
- Prometheus metrics: `http://127.0.0.1:6060/metrics`
- CAPI disabled (fully offline)

Keep this terminal open. Use a **second terminal** for CLI commands.

### Option B — All-in-one dev mode (engine + simple UI)

```powershell
.\scripts\cybersec-dev.ps1
```

- Starts engine if not running
- Opens **http://127.0.0.1:3000** (custom CyberSec dashboard)

### Option C — CyberSec Web UI (community dashboard)

```powershell
# Terminal 1 — engine
.\scripts\cybersec-run.ps1

# Terminal 2 — full dashboard
.\scripts\cybersec-ui.ps1
```

- Opens **http://127.0.0.1:3001**

### Option D — Official cloud console (requires CyberSec account)

```powershell
.\scripts\cybersec-console-enroll.ps1
# Accept enrollment at CyberSec Cloud Console

.\scripts\cybersec-run-capi.ps1
```

---

## 8. Testing — Simulated Attacks (Safe Local Demo)

This is the **safest** way to test. No real hacking tools needed.

### Test 1 — Automatic alert injection

With the engine running:

```powershell
.\scripts\cybersec-test-alert.ps1
```

**What it does:**
1. Appends 6 SSH "Failed password" lines from IP `203.0.113.99` to `.local/logs/sample.log`
2. Waits 2 seconds for the engine to process
3. Lists alerts and decisions

**Expected result:**

```
Alerts:  crowdsecurity/ssh-bf (SSH Bruteforce)
Decision: ban on 203.0.113.99 for 4h
```

### Test 2 — Manual log injection

Add lines to the sample log (engine must be running and tailing the file):

```powershell
Add-Content .\.local\logs\sample.log "Jan  1 00:05:01 localhost sshd[9999]: Failed password for invalid user hacker from 198.51.100.77 port 22 ssh2"
```

Repeat **5 times** with the **same IP** within a few seconds to trigger `ssh-bf`.

### Test 3 — Verify via CLI

```powershell
$config = ".\.local\cybersec-local.yaml"

.\bin\cybercli.exe -c $config alerts list
.\bin\cybercli.exe -c $config decisions list
.\bin\cybercli.exe -c $config metrics
.\bin\cybercli.exe -c $config explain --file .\.local\logs\sample.log --type syslog
```

`explain` shows how a log line flows through parsers and scenarios **without** needing the engine running.

### Test 4 — Check simulation mode

```powershell
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml simulation status
```

If `simulation: true`, alerts appear but **no ban decisions** are created. Your setup has `simulation: false`, so bans are real in the database (but not enforced on the network without a bouncer).

### Test 5 — Dashboard verification

1. Run `.\scripts\cybersec-dev.ps1`
2. Open http://127.0.0.1:3000
3. Confirm alert count and banned IP appear in the UI

---

## 9. Testing — Real Attacks (Production-Style)

> **Warning:** Only test on systems you own or have explicit permission to test. Unauthorized scanning or brute-forcing is illegal.

### Scenario A — Real SSH server (Linux VM or WSL)

This is how CyberSec is used in production.

1. **Install CyberSec/CyberSec** on a Linux server with SSH enabled.
2. **Configure acquisition** for `/var/log/auth.log`:

```yaml
# acquis.yaml
filenames:
  - /var/log/auth.log
labels:
  type: syslog
```

3. **Install collections:** `cybercli collections install crowdsecurity/sshd`
4. **Install firewall bouncer:** e.g. `crowdsecurity/firewall-bouncer-iptables`
5. **Run engine** and bouncer as services.
6. **Simulate attack** from another machine (your own test VM):

```bash
# From attacker VM — use a tool like hydra against YOUR test server only
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://YOUR_SERVER_IP -t 4
```

7. **Verify on server:**

```bash
cybercli alerts list
cybercli decisions list
iptables -L  # or nft list ruleset — should show CyberSec chain blocking the IP
```

### Scenario B — Windows with real logs

For production on Windows:

1. Install as a service using `config\config_win.yaml` (paths under `C:\ProgramData\CyberSec\`).
2. Configure acquisition for:
   - IIS logs
   - Windows Event Log (via dedicated acquis module)
   - Custom application logs
3. Install a Windows-compatible bouncer (e.g. Windows Firewall bouncer).
4. Point acquisition away from `sample.log` to real log paths.

Example acquis for a web server log:

```yaml
filenames:
  - C:/inetpub/logs/LogFiles/W3SVC1/*.log
labels:
  type: iis
```

Install matching Hub collection: `crowdsecurity/iis`.

### Scenario C — Use Hub scenario tests (no live attack)

CyberSec Hub items include test assertions:

```powershell
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml hub test crowdsecurity/sshd
```

This validates parsers and scenarios against known test log samples — **no network attack required**.

### Scenario D — Connect to CyberSec Console (see real community intel)

1. Enroll: `.\scripts\cybersec-console-enroll.ps1`
2. Run with CAPI: `.\scripts\cybersec-run-capi.ps1`
3. View alerts at CyberSec Cloud Console

Your instance can receive blocklists from the global CyberSec community (millions of reported malicious IPs).

### What "real blocking" requires

| Component | Local demo setup | Production |
|-----------|------------------|------------|
| Engine | ✅ Running | ✅ Running |
| Scenarios | ✅ ssh-bf | ✅ Many collections |
| Decisions in DB | ✅ Yes | ✅ Yes |
| Bouncer | ❌ Not installed | ✅ firewall/nginx/WAF |
| Actual packet drop | ❌ No | ✅ Yes |

**Without a bouncer, decisions exist only in the database** — useful for monitoring and learning, but attackers are not blocked at the network level.

---

## 10. Dashboards & Monitoring

| UI | URL | Script | Notes |
|----|-----|--------|-------|
| CyberSec simple dashboard | http://127.0.0.1:3000 | `cybersec-dev.ps1` or `cybersec-ui.ps1` | Custom HTML, reads LAPI via cybercli |
| CyberSec Web UI (community) | http://127.0.0.1:3001 | `cybersec-ui.ps1` | Full-featured local dashboard |
| Official CyberSec Console | CyberSec Cloud Console | `cybersec-run-capi.ps1` | Cloud-hosted, requires enrollment |
| Prometheus metrics | http://127.0.0.1:6060/metrics | (automatic with engine) | For Grafana/monitoring |

---

## 11. CLI Reference

All commands use:

```powershell
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml <command>
```

| Command | Description |
|---------|-------------|
| `version` | Show CyberSec version and build info |
| `metrics` | Show processing statistics |
| `alerts list` | List security alerts |
| `decisions list` | List ban/captcha decisions |
| `hub list` | Installed parsers/scenarios/collections |
| `hub update` | Update Hub index from internet |
| `collections install crowdsecurity/sshd` | Install SSH detection pack |
| `explain --file <log> --type syslog` | Trace log through parsers/scenarios |
| `simulation status` | Check if simulation mode is on |
| `capi register` | Register with Central API |
| `console enroll` | Enroll in cloud console |
| `bouncers list` | List connected bouncers (none in local demo) |
| `machines list` | List LAPI registered machines |

---

## 12. Troubleshooting

### Engine won't start

```powershell
# Check config is valid
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml config show

# Check port 8080 is free
netstat -an | findstr 8080
```

### No alerts after adding log lines

1. Confirm engine is running (`cybersec-run.ps1`).
2. Confirm lines match SSH failed-auth format (see `sample.log`).
3. Use **5+ failures from the same IP** within ~10 seconds.
4. Check metrics: `cybercli metrics` — look for `parsed_lines` increasing.
5. Run `explain` to verify parser output.

### Hub install fails on Windows

The fork includes a **Windows symlink workaround** in `pkg/hubops/enable.go` — hub files are copied instead of symlinked. Re-run setup:

```powershell
.\scripts\cybersec-setup.ps1
```

### Dashboard shows empty data

1. Engine must be running on port 8080.
2. Run `cybercli alerts list` — if CLI shows data but UI does not, restart the UI script.
3. For port 3000 vs 3001 conflicts, stop the other UI first.

### CAPI / console enrollment fails

- Requires internet access.
- Create a free account at CyberSec Cloud Console first.
- Run `cybersec-console-enroll.ps1` and accept the enrollment in the browser.

---

## 13. File & Folder Map

```
cybersec/                           # Repository root
├── bin/
│   ├── cybersec.exe           # Security engine (built)
│   └── cybercli.exe                  # CLI (built)
├── cmd/
│   ├── engine/                      # Engine source (built as cybersec)
│   └── cli/                         # CLI source (built as cybercli)
├── pkg/
│   └── branding/branding.go       # CyberSec naming
├── config/
│   ├── cybersec-local.yaml       # Local dev config template
│   ├── acquis_local_dev.yaml      # File-based log acquisition
│   └── config_win.yaml            # Production Windows paths
├── scripts/
│   └── cybersec-*.ps1            # All automation scripts
├── ui/
│   └── index.html                 # Simple dashboard
├── .local/                        # Created by setup (gitignored)
│   ├── cybersec-local.yaml
│   ├── config/hub/                # Detection rules
│   ├── data/cybersec.db
│   └── logs/sample.log
├── instruction.md                 # This file
└── README.md                      # Quick start summary
```

---

## Quick Reference — Full Local Test Flow

```powershell
# 1. One-time setup
.\scripts\cybersec-build.ps1
.\scripts\cybersec-setup.ps1

# 2. Start engine (Terminal 1)
.\scripts\cybersec-run.ps1

# 3. Trigger test attack (Terminal 2)
.\scripts\cybersec-test-alert.ps1

# 4. View results
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml alerts list
.\bin\cybercli.exe -c .\.local\cybersec-local.yaml decisions list

# 5. Optional — open dashboard
.\scripts\cybersec-dev.ps1
# Browser: http://127.0.0.1:3000
```

---

## Summary

| Question | Answer |
|----------|--------|
| What is CyberSec? | A rebranded CyberSec fork for learning and Windows local dev |
| Is detection real? | **Yes** — same Hub parsers and scenarios as production CyberSec |
| Is current setup a demo? | **Partly** — uses fake log file; no bouncer for network blocking |
| Can it stop real attacks? | **Yes**, when pointed at real logs + bouncer installed |
| How to test safely now? | Run `cybersec-test-alert.ps1` and check alerts/decisions |
| How to test like production? | Linux server + real auth.log + firewall bouncer + controlled brute force |

For questions or next steps (installing a bouncer, monitoring IIS, deploying as a Windows service), extend acquisition and Hub collections following [CyberSec documentation](CyberSec documentation).
