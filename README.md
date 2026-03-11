# pudo
Privilege User DO — more powerful than sudo

# pudo — Privilege User DO

> **More powerful than sudo** — fine-grained Linux capabilities, HMAC-signed session tokens, ambient cap inheritance, safe file editing, and a full audit trail.

```
pudo id                              # run as root
pudo -u www-data stat /var/www       # run as another user
pudo -C cap_net_raw ping 8.8.8.8    # only cap_net_raw — no full root
pudo -e /etc/hosts                   # safe privileged file edit
pudo --show-caps                     # all Linux capability names
```

---

## Why pudo instead of sudo?

| Feature | sudo | pudo |
|---|---|---|
| Fine-grained capabilities | ❌ all-or-nothing root | ✅ grant only what's needed |
| Token security | TTY-based | HMAC-signed, boot-id-bound, tty-scoped |
| Ambient cap inheritance | ❌ | ✅ child processes inherit caps |
| Safe file editing | `sudoedit` | `pudo -e` — atomic write + audit |
| Environment stripping | partial | strips `LD_*`, `PYTHON*`, `PERL5*`, `MALLOC_*`, etc. |
| Binary safety check | ❌ | refuses world-writable binaries & dirs |
| Rule files | single `/etc/sudoers` | `/etc/pudo/rules.d/*.rules` — multiple, readable |
| Audit log | syslog | `/var/log/pudo.log` + syslog, fsync'd |

---

## Architecture

```
/usr/local/bin/pudo          ← SUID root C binary (pudo_wrapper.c)
/usr/local/lib/pudo/
  pudo_internal.py           ← Python engine (all logic lives here)
/etc/pudo/
  pudo.conf                  ← main configuration
  rules.d/
    00-defaults.rules        ← default rules (%wheel, %sudo)
    local.rules              ← your custom rules
/var/log/pudo.log            ← audit trail
/run/pudo/                   ← session tokens (sticky 1777)
```

Why a C wrapper + Python engine?  
Linux ignores the SUID bit on interpreted scripts (`#!`). The tiny C binary holds the SUID bit, calls `prctl(PR_SET_KEEPCAPS)` so capabilities survive the UID transition, then execs the Python engine.

---

## Installation

### Requirements
- Python 3.10+
- gcc
- libcap (`sudo pacman -S libcap` / `sudo apt install libcap2-bin`)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/pudo.git
cd pudo
sudo bash install.sh
```

The installer will:
1. Compile `pudo_wrapper.c` with gcc
2. Install the SUID binary to `/usr/local/bin/pudo` (mode `4755 root:root`)
3. Install the Python engine to `/usr/local/lib/pudo/pudo_internal.py`
4. Install config to `/etc/pudo/` (mode `700`)
5. Apply file capabilities via `setcap`
6. Create `/run/pudo/` (sticky `1777`) and `/var/log/pudo.log`

---

## Usage

```bash
# Run as root
pudo id

# Run as another user
pudo -u www-data id

# Run with a specific primary group
pudo -g docker id

# Restrict to specific Linux capabilities only (no full root)
pudo -C cap_net_raw,cap_net_admin tcpdump -i eth0

# Extended token TTL (10 minutes)
pudo -t 600 bash

# Non-interactive (token must already exist)
pudo -n systemctl restart nginx

# Safe privileged file edit (like sudoedit)
pudo -e /etc/nginx/nginx.conf

# List your allowed commands
pudo -l

# Revoke session token
pudo -k

# Open a privileged shell
pudo --shell

# View audit log (root only)
pudo --log

# List all Linux capability names
pudo --show-caps

# Version
pudo -v
```

---

## Rule File Format

`/etc/pudo/rules.d/local.rules`:

```
# WHO   HOST=(TARGET_USER[:GROUP])   [OPTIONS]   COMMANDS

# Full access for wheel group
%wheel  ALL=(ALL:ALL)  ALL

# Passwordless systemctl for wheel
%wheel  ALL=(root)  NOPASSWD  /usr/bin/systemctl

# netops group — raw network tools WITHOUT full root
# Only cap_net_raw + cap_net_admin — nothing else
%netops  ALL=(root)  CAPS=cap_net_raw,cap_net_admin  NOPASSWD  /usr/sbin/tcpdump

# Single user, single command
alice  ALL=(root)  NOPASSWD  /usr/bin/apt update

# Full passwordless access for p1rater
p1rater  ALL=(ALL:ALL)  NOPASSWD  ALL
```

**Options:**
- `NOPASSWD` — skip password prompt
- `CAPS=cap1,cap2` — restrict execution to only these Linux capabilities

---

## Capability Restriction

The most powerful feature. Instead of giving full root, you can grant only the specific Linux kernel capabilities a command needs:

```bash
# ping needs cap_net_raw — give only that
pudo -C cap_net_raw ping 8.8.8.8

# tcpdump needs cap_net_raw + cap_net_admin
pudo -C cap_net_raw,cap_net_admin tcpdump -i wlan0

# bind to port 80 without root
pudo -C cap_net_bind_service python3 -m http.server 80
```

Run `pudo --show-caps` to see all 41 recognised capabilities with their current status.

---

## Uninstall

```bash
sudo rm -f /usr/local/bin/pudo
sudo rm -rf /usr/local/lib/pudo
sudo rm -rf /etc/pudo
sudo rm -f /var/log/pudo.log
```

---

---

## Author

**p1rater** — p1rater@bluearch.network  
Part of the [BlueArch Linux](https://bluearch.network) project.
