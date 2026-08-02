# CyberSec

**CyberSec** is an IDS/IPS security platform that detects malicious behavior and automatically blocks bad IPs through a Windows Firewall bouncer.

Built for local development, demos, and hands-on security testing on Windows.

## Quick Start

```powershell
cd C:\Users\Sasikiran\Documents\crowdsec

# First time only
.\scripts\run.ps1 setup

# Start full stack (Admin — keep window open)
.\scripts\run.ps1 start
```

- Dashboard: http://127.0.0.1:3000  
- Prometheus: http://127.0.0.1:6060/metrics  
- Stop: `.\scripts\run.ps1 stop`

## Two-Device Attack Demo

See **[ATTACK-DEMO.md](ATTACK-DEMO.md)** for the full step-by-step guide.

| Host | Remote device (copy `run.ps1` only) |
|------|-------------------------------------|
| `.\scripts\run.ps1 start` | `.\run.ps1 attack -HostIp HOST_LAN_IP` |
| `.\scripts\run.ps1 export` | Port scan + TCP flood → auto ban |
| Watch dashboard | Connections blocked after ban |

**Single PC:** `.\scripts\run.ps1 simulate 203.0.113.99`

## Commands

```powershell
.\scripts\run.ps1 setup      # First-time build and config
.\scripts\run.ps1 start      # Engine + honeypot + bouncer + UI
.\scripts\run.ps1 info       # Your LAN IP
.\scripts\run.ps1 status     # Bans and firewall rules
.\scripts\run.ps1 simulate IP  # Test detection without 2nd device
.\scripts\run.ps1 export     # Copy run.ps1 to Desktop for remote attacker
.\scripts\run.ps1 stop       # Stop all services
```

## Architecture

```
Remote attack  →  Honeypot :9999  →  attack.log  →  Engine  →  Ban  →  Firewall  →  Block IP
                                                      ↓
                                              Dashboard :3000 + Prometheus :6060
```

## Documentation

- **[ATTACK-DEMO.md](ATTACK-DEMO.md)** — Two-device automatic attack demo
- **[instruction.md](instruction.md)** — Full project reference

## License

Based on CyberSec (MIT License). See upstream project for full license terms.

