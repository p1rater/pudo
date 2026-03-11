#!/usr/bin/env python3
# =============================================================================
#  pudo_internal.py — Privilege User DO  (internal engine)
#  Invoked by the SUID C wrapper at /usr/local/bin/pudo
#
#  More powerful than sudo:
#    • Fine-grained Linux capabilities  (grant only what's needed)
#    • HMAC-signed session tokens       (tty-scoped, boot-id-bound)
#    • Ambient capability inheritance   (children also get the caps)
#    • Safe file editing                (atomic write + audit)
#    • World-writable binary detection  (prevents hijack attacks)
#    • Clean environment by default     (strips LD_*, PYTHON*, etc.)
#    • Full audit trail → /var/log/pudo.log + syslog
#
#  Usage:
#    pudo <command>                     run as root
#    pudo -u <user> <command>           run as another user
#    pudo -g <group> <command>          switch primary group
#    pudo -C cap_net_raw,cap_net_admin <cmd>   restrict to these caps only
#    pudo -t 600 <command>              10-minute token cache
#    pudo -n <command>                  non-interactive (token must exist)
#    pudo -E <command>                  preserve environment
#    pudo -e /etc/hosts                 safe privileged edit (pudo edit)
#    pudo -l                            list allowed commands for this user
#    pudo -k                            revoke token (logout)
#    pudo --shell                       open a privileged shell
#    pudo --login                       simulate login shell
#    pudo --log                         show last 100 audit entries (root only)
#    pudo --show-caps                   list all recognised capability names
#    pudo -v                            show version
# =============================================================================

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import errno
import grp
import hashlib
import hmac
import json
import os
import pwd
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import syslog
import time
from pathlib import Path
from typing import Any

# ─── Version ──────────────────────────────────────────────────────────────────
VERSION = "2.0.0"

# ─── Paths ────────────────────────────────────────────────────────────────────
CONF_DIR   = Path("/etc/pudo")
CONF_FILE  = CONF_DIR / "pudo.conf"
RULES_DIR  = CONF_DIR / "rules.d"
TOKEN_DIR  = Path("/run/pudo")
AUDIT_LOG  = Path("/var/log/pudo.log")

# ─── Defaults (can be overridden in pudo.conf) ────────────────────────────────
DEFAULT_TOKEN_TTL  = 300   # seconds
DEFAULT_MAX_TRIES  = 3
DEFAULT_AUTH_DELAY = 0.5   # seconds between failed attempts

# ─── ANSI colours ─────────────────────────────────────────────────────────────
_C  = "\033[1;36m[pudo]\033[0m"   # cyan  — info
_E  = "\033[1;31m[pudo]\033[0m"   # red   — error
_OK = "\033[1;32m[pudo]\033[0m"   # green — success
_W  = "\033[1;33m[pudo]\033[0m"   # yellow — warning

# ─── Linux capability names → bit numbers (kernel ABI) ───────────────────────
CAPS: dict[str, int] = {
    "cap_chown":              0,
    "cap_dac_override":       1,
    "cap_dac_read_search":    2,
    "cap_fowner":             3,
    "cap_fsetid":             4,
    "cap_kill":               5,
    "cap_setgid":             6,
    "cap_setuid":             7,
    "cap_setpcap":            8,
    "cap_linux_immutable":    9,
    "cap_net_bind_service":   10,
    "cap_net_broadcast":      11,
    "cap_net_admin":          12,
    "cap_net_raw":            13,
    "cap_ipc_lock":           14,
    "cap_ipc_owner":          15,
    "cap_sys_module":         16,
    "cap_sys_rawio":          17,
    "cap_sys_chroot":         18,
    "cap_sys_ptrace":         19,
    "cap_sys_pacct":          20,
    "cap_sys_admin":          21,
    "cap_sys_boot":           22,
    "cap_sys_nice":           23,
    "cap_sys_resource":       24,
    "cap_sys_time":           25,
    "cap_sys_tty_config":     26,
    "cap_mknod":              27,
    "cap_lease":              28,
    "cap_audit_write":        29,
    "cap_audit_control":      30,
    "cap_setfcap":            31,
    "cap_mac_override":       32,
    "cap_mac_admin":          33,
    "cap_syslog":             34,
    "cap_wake_alarm":         35,
    "cap_block_suspend":      36,
    "cap_audit_read":         37,
    "cap_perfmon":            38,
    "cap_bpf":                39,
    "cap_checkpoint_restore": 40,
}

# capset(2) kernel ABI
_CAP_VERSION_3  = 0x20080522
_HEADER_FMT     = "=II"   # version, pid
_DATA_FMT       = "=II"   # effective, permitted  (×2 for 64-bit caps)


# =============================================================================
#  Exceptions
# =============================================================================

class PudoError(Exception):
    pass

class AccessDenied(PudoError):
    pass


# =============================================================================
#  Configuration loader
# =============================================================================

def _load_config() -> dict:
    cfg = {
        "token_timeout": DEFAULT_TOKEN_TTL,
        "max_retries":   DEFAULT_MAX_TRIES,
        "auth_delay":    DEFAULT_AUTH_DELAY,
        "env_policy":    "strict",
        "blacklist":     [],
    }
    try:
        for line in CONF_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([\w_]+)\s*=\s*(.+)$", line)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2).strip()
            if key == "token_timeout":
                cfg["token_timeout"] = int(val)
            elif key == "max_retries":
                cfg["max_retries"] = int(val)
            elif key == "auth_delay":
                cfg["auth_delay"] = float(val)
            elif key == "env_policy":
                cfg["env_policy"] = val.lower()
            elif key == "blacklist":
                cfg["blacklist"] = [b.strip() for b in val.split(",")]
    except FileNotFoundError:
        pass
    except Exception as e:
        sys.stderr.write(f"{_W} Config warning: {e}\n")
    return cfg


CFG: dict = {}   # populated in main()


# =============================================================================
#  Token store  — HMAC-signed, tty-scoped, boot-id-bound
# =============================================================================

class TokenStore:

    def __init__(self, uid: int, ttl: int):
        self.uid = uid
        self.ttl = ttl
        TOKEN_DIR.mkdir(mode=0o1777, parents=True, exist_ok=True)
        try:
            tty_id = os.ttyname(sys.stdin.fileno()).replace("/", "_")
        except Exception:
            tty_id = "notty"
        self._path = TOKEN_DIR / f"{uid}_{tty_id}.tok"

    # ── internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _boot_id() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except Exception:
            return "unknown"

    def _sign(self, ts: float) -> str:
        msg = f"{self.uid}:{ts}:{self._boot_id()}".encode()
        key = hashlib.sha256(msg).digest()
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    # ── public ────────────────────────────────────────────────────────────────

    def valid(self) -> bool:
        try:
            s = self._path.stat()
            if s.st_uid != self.uid:
                return False
            if stat.S_IMODE(s.st_mode) != 0o600:
                return False
            data = json.loads(self._path.read_text())
            if data.get("uid") != self.uid:
                return False
            ts = float(data["ts"])
            if time.time() - ts > self.ttl:
                return False
            return hmac.compare_digest(data["sig"], self._sign(ts))
        except Exception:
            return False

    def grant(self) -> None:
        ts = time.time()
        self._path.write_text(json.dumps({"uid": self.uid, "ts": ts,
                                           "sig": self._sign(ts)}))
        os.chmod(self._path, 0o600)
        os.chown(self._path, self.uid, -1)

    def revoke(self) -> None:
        try:
            self._path.unlink()
        except FileNotFoundError:
            pass


# =============================================================================
#  Authentication
# =============================================================================

def _shadow_hash(username: str) -> str | None:
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            parts = line.split(":")
            if parts[0] == username and len(parts) >= 2:
                return parts[1] or None
    except PermissionError:
        return None
    return None


def _verify_password(username: str, password: str) -> bool:
    h = _shadow_hash(username)
    if h:
        if h in ("!", "!!", "*"):
            return False
        try:
            import crypt
            return crypt.crypt(password, h) == h
        except ImportError:
            pass

    # PAM fallback via su
    try:
        proc = subprocess.Popen(
            ["su", "-c", "true", username],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.communicate(input=(password + "\n").encode(), timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


def authenticate(caller: str, token: TokenStore, non_interactive: bool) -> None:
    """Authenticate or raise AccessDenied."""
    if token.valid():
        return

    if non_interactive:
        raise AccessDenied("No valid token and --non-interactive flag is set.")

    sys.stderr.write(f"\n{_C} Authentication required for \033[1m{caller}\033[0m\n")

    max_tries  = CFG.get("max_retries", DEFAULT_MAX_TRIES)
    auth_delay = CFG.get("auth_delay",  DEFAULT_AUTH_DELAY)

    for attempt in range(1, max_tries + 1):
        try:
            import getpass
            pw = getpass.getpass(f"[pudo] Password for {caller}: ")
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\n")
            raise AccessDenied("Authentication cancelled.")

        if _verify_password(caller, pw):
            token.grant()
            return

        sys.stderr.write(f"{_E} Wrong password ({attempt}/{max_tries})\n")
        time.sleep(auth_delay * attempt)

    raise AccessDenied(f"Authentication failed after {max_tries} attempts.")


# =============================================================================
#  Policy / rule engine
# =============================================================================
#
#  Rule file format  (/etc/pudo/rules.d/*.rules):
#
#    WHO   HOST=(TARGET_USER[:TARGET_GROUP])  [NOPASSWD]  [CAPS=c1,c2]  COMMANDS
#
#  Examples:
#    %wheel   ALL=(ALL:ALL)   ALL
#    ali      ALL=(root)      NOPASSWD   /usr/bin/systemctl
#    %netops  ALL=(root)      CAPS=cap_net_raw,cap_net_admin  NOPASSWD  /usr/sbin/tcpdump
# ─────────────────────────────────────────────────────────────────────────────

class Rule:
    __slots__ = ("who", "hosts", "target_user", "target_group",
                 "nopasswd", "caps", "commands")

    def __init__(self, who, hosts, target_user, target_group,
                 nopasswd, caps, commands):
        self.who          = who
        self.hosts        = hosts
        self.target_user  = target_user
        self.target_group = target_group
        self.nopasswd     = nopasswd
        self.caps         = caps       # list[str] | None
        self.commands     = commands   # list[str]


def _parse_rule_file(path: Path) -> list[Rule]:
    rules: list[Rule] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = re.findall(r'"[^"]*"|\S+', line)
        if len(tokens) < 3:
            continue

        who = tokens[0]

        m = re.match(r"^(.+?)=\((\S+?)(?::(\S+))?\)$", tokens[1])
        if not m:
            continue
        hosts, target_user, target_group = m.group(1), m.group(2), m.group(3)

        nopasswd = False
        caps: list[str] | None = None
        commands: list[str] = []

        for tok in tokens[2:]:
            upper = tok.upper()
            if upper == "NOPASSWD":
                nopasswd = True
            elif upper.startswith("CAPS="):
                caps = [c.strip().lower() for c in tok[5:].split(",") if c.strip()]
            else:
                commands.append(tok)

        if commands:
            rules.append(Rule(who, hosts, target_user, target_group,
                              nopasswd, caps, commands))
    return rules


def load_rules() -> list[Rule]:
    all_rules: list[Rule] = []
    if RULES_DIR.is_dir():
        for p in sorted(RULES_DIR.glob("*.rules")):
            try:
                all_rules.extend(_parse_rule_file(p))
            except Exception as e:
                sys.stderr.write(f"{_W} Rule parse error {p.name}: {e}\n")
    return all_rules


def _user_groups(username: str) -> list[str]:
    groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
    try:
        primary = grp.getgrgid(pwd.getpwnam(username).pw_gid).gr_name
        if primary not in groups:
            groups.append(primary)
    except KeyError:
        pass
    return groups


def check_policy(caller: str, target_user: str, target_group: str | None,
                 command_bin: str, rules: list[Rule], hostname: str) -> Rule | None:
    caller_groups = _user_groups(caller)
    for rule in rules:
        # who
        if rule.who != "ALL" and rule.who != caller:
            if rule.who.startswith("%"):
                if rule.who[1:] not in caller_groups:
                    continue
            else:
                continue
        # host
        if rule.hosts != "ALL" and rule.hosts != hostname:
            continue
        # target user
        if rule.target_user != "ALL" and rule.target_user != target_user:
            continue
        # target group
        if target_group and rule.target_group:
            if rule.target_group != "ALL" and rule.target_group != target_group:
                continue
        # command
        for allowed in rule.commands:
            if allowed == "ALL":
                return rule
            a_abs = os.path.abspath(allowed)
            c_abs = os.path.abspath(command_bin)
            if a_abs == c_abs or os.path.basename(allowed) == os.path.basename(command_bin):
                return rule
    return None


# =============================================================================
#  Linux capabilities  (capset + ambient)
# =============================================================================

def _build_cap_mask(cap_names: list[str]) -> int:
    mask = 0
    for name in cap_names:
        bit = CAPS.get(name.lower())
        if bit is None:
            raise PudoError(f"Unknown capability: {name!r}  (run 'pudo --show-caps')")
        mask |= (1 << bit)
    return mask


def apply_caps(cap_names: list[str]) -> None:
    """
    Drop all capabilities except cap_names.
    Must be called AFTER setuid/setgid so we still have CAP_SETPCAP.
    Sequence:
      1. capset — set permitted/effective to only our chosen caps
      2. prctl(PR_SET_AMBIENT) — so child processes inherit them too
    """
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    mask   = _build_cap_mask(cap_names)
    lo     = mask & 0xFFFF_FFFF
    hi     = (mask >> 32) & 0xFFFF_FFFF

    header = struct.pack(_HEADER_FMT, _CAP_VERSION_3, 0)
    # Two __user_cap_data_struct entries (low + high 32-bit halves)
    # each: effective, permitted, inheritable  — we set all three the same
    data   = (struct.pack("=III", lo, lo, lo) +
              struct.pack("=III", hi, hi, hi))

    hdr_buf  = ctypes.create_string_buffer(header)
    data_buf = ctypes.create_string_buffer(data)

    NR_capset = 126   # x86_64
    ret = libc.syscall(NR_capset, hdr_buf, data_buf)
    if ret != 0:
        err = ctypes.get_errno()
        raise PudoError(f"capset(2) failed: {os.strerror(err)}")

    # Set ambient capabilities (Linux 4.3+)
    PR_CAP_AMBIENT       = 47
    PR_CAP_AMBIENT_RAISE = 2
    PR_CAP_AMBIENT_CLEAR_ALL = 4

    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    for name in cap_names:
        bit = CAPS[name.lower()]
        r = libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, bit, 0, 0)
        if r != 0:
            sys.stderr.write(f"{_W} Could not raise ambient cap {name}: "
                             f"{os.strerror(ctypes.get_errno())}\n")


def read_current_caps() -> list[str]:
    """Read effective caps from /proc/self/status."""
    try:
        text = Path("/proc/self/status").read_text()
        m = re.search(r"CapEff:\s+([0-9a-f]+)", text)
        if not m:
            return []
        mask = int(m.group(1), 16)
        return [name for name, bit in sorted(CAPS.items(), key=lambda x: x[1])
                if mask & (1 << bit)]
    except Exception:
        return []


# =============================================================================
#  Audit
# =============================================================================

def audit(caller: str, target: str, command: str,
          result: str, caps: list[str] | None = None) -> None:
    ts       = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        tty = os.ttyname(sys.stdin.fileno())
    except Exception:
        tty = "notty"
    caps_str = ",".join(caps) if caps else "ALL"
    pid      = os.getpid()
    record   = (f"{ts} pid={pid} caller={caller} target={target} "
                f"tty={tty} caps=[{caps_str}] cmd={command!r} result={result}\n")
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(AUDIT_LOG),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        os.write(fd, record.encode())
        os.fsync(fd)
        os.close(fd)
    except Exception:
        pass
    try:
        syslog.openlog("pudo", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, record.strip())
        syslog.closelog()
    except Exception:
        pass


# =============================================================================
#  Execution core
# =============================================================================

_DANGEROUS_ENV = re.compile(
    r"^(LD_|CDPATH|ENV|BASH_ENV|PYTHON|PERL5|RUBYLIB|IFS|"
    r"SHELLOPTS|PS4|TERMINFO|DBUS_SESSION_BUS_ADDRESS|"
    r"GCONV_PATH|NLSPATH|LOCPATH|MALLOC_)"
)


def _clean_env(caller_env: dict, target_user: str, preserve: bool) -> dict:
    if preserve:
        return {k: v for k, v in caller_env.items()
                if not _DANGEROUS_ENV.match(k)}
    try:
        pw = pwd.getpwnam(target_user)
        env = {
            "HOME":    pw.pw_dir,
            "USER":    pw.pw_name,
            "LOGNAME": pw.pw_name,
            "SHELL":   pw.pw_shell or "/bin/bash",
            "PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM":    caller_env.get("TERM", "xterm-256color"),
            "LANG":    caller_env.get("LANG", "en_US.UTF-8"),
            "LC_ALL":  caller_env.get("LC_ALL", ""),
        }
    except KeyError:
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    env["PUDO_USER"]    = caller_env.get("USER", "")
    env["PUDO_COMMAND"] = " ".join(sys.argv[1:])
    return env


def _resolve(cmd: str) -> str:
    """Return absolute path of cmd, raise PudoError if not found."""
    if os.sep in cmd:
        p = os.path.abspath(cmd)
        if os.path.isfile(p):
            return p
        raise PudoError(f"Not found: {p!r}")
    found = shutil.which(cmd)
    if not found:
        raise PudoError(f"Command not found in PATH: {cmd!r}")
    return found


def _safety_check(path: str) -> None:
    """Refuse world-writable binaries and unsafe parent directories."""
    s = os.stat(path)
    if s.st_mode & stat.S_IWOTH:
        raise PudoError(f"Refusing world-writable binary: {path}")
    ds = os.stat(os.path.dirname(os.path.abspath(path)))
    if (ds.st_mode & stat.S_IWOTH) and not (ds.st_mode & stat.S_ISVTX):
        raise PudoError(f"Refusing binary in world-writable directory: {path}")


def exec_privileged(
    target_user:  str,
    target_group: str | None,
    argv:         list[str],
    cap_list:     list[str] | None,
    preserve_env: bool,
    login_shell:  bool,
) -> None:
    """
    Full privilege transition and exec.
    Order matters on Linux:
      prctl(KEEPCAPS) — done in C wrapper before exec
      setgroups → setresgid → setresuid
      capset (now we're the target user but still have caps because KEEPCAPS)
      execve
    """
    # Open login shell if no command given
    if not argv or login_shell:
        try:
            sh = pwd.getpwnam(target_user).pw_shell or "/bin/bash"
        except KeyError:
            sh = "/bin/bash"
        if login_shell:
            argv = ["-" + os.path.basename(sh)] + (argv or [])
        else:
            argv = [sh]

    bin_path = _resolve(argv[0])
    _safety_check(bin_path)

    # Blacklist check
    blacklist = CFG.get("blacklist", [])
    for b in blacklist:
        if os.path.abspath(b) == bin_path:
            raise PudoError(f"Command is blacklisted by pudo policy: {bin_path}")

    # Resolve IDs
    try:
        pw = pwd.getpwnam(target_user)
    except KeyError:
        raise PudoError(f"Unknown user: {target_user!r}")

    uid = pw.pw_uid
    gid = pw.pw_gid

    if target_group:
        try:
            gid = grp.getgrnam(target_group).gr_gid
        except KeyError:
            raise PudoError(f"Unknown group: {target_group!r}")

    supp = [g.gr_gid for g in grp.getgrall() if pw.pw_name in g.gr_mem]
    if gid not in supp:
        supp.insert(0, gid)

    env = _clean_env(dict(os.environ), target_user, preserve_env)

    # ── privilege drop ────────────────────────────────────────────────────────
    try:
        # prctl KEEPCAPS was set by the C wrapper BEFORE this process ran,
        # so capabilities survive the uid change below.
        os.setgroups(supp)
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
    except PermissionError as e:
        raise PudoError(f"Privilege transition failed: {e}")

    # ── capability restriction ────────────────────────────────────────────────
    if cap_list is not None:
        try:
            apply_caps(cap_list)
        except PudoError as e:
            sys.stderr.write(f"{_W} capset warning: {e}\n"
                             f"{_W} Continuing with full capabilities.\n")

    # ── exec ──────────────────────────────────────────────────────────────────
    argv[0] = bin_path
    try:
        os.chdir(pw.pw_dir)
    except Exception:
        pass
    os.execve(bin_path, argv, env)
    raise PudoError(f"execve returned unexpectedly for {bin_path}")


# =============================================================================
#  Secure file editor  (pudo -e / pudo edit)
# =============================================================================

def secure_edit(filepath: str, caller_name: str) -> None:
    """
    sudoedit-equivalent:
      1. Copy target → tmp (owned by caller)
      2. Fork child, drop to caller uid, exec $EDITOR
      3. If file changed: atomic rename back to target
      4. Audit
    """
    target = Path(filepath)
    editor = (os.environ.get("VISUAL") or
              os.environ.get("EDITOR") or
              shutil.which("nano") or
              "/usr/bin/vi")

    try:
        caller_pw = pwd.getpwnam(caller_name)
    except KeyError:
        raise PudoError(f"Unknown caller: {caller_name!r}")

    try:
        original = target.read_bytes()
    except FileNotFoundError:
        original = b""

    orig_hash = hashlib.sha256(original).hexdigest()

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pudo_edit", delete=False) as tf:
        tf.write(original)
        tmp = tf.name

    os.chown(tmp, caller_pw.pw_uid, caller_pw.pw_gid)
    os.chmod(tmp, 0o600)

    child = os.fork()
    if child == 0:
        os.setresuid(caller_pw.pw_uid, caller_pw.pw_uid, caller_pw.pw_uid)
        os.execvp(editor, [editor, tmp])
        sys.exit(1)

    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        Path(tmp).unlink(missing_ok=True)
        raise PudoError("Editor exited with error — changes not saved.")

    edited   = Path(tmp).read_bytes()
    new_hash = hashlib.sha256(edited).hexdigest()

    if new_hash == orig_hash:
        print(f"{_C} No changes — file not written.")
        Path(tmp).unlink(missing_ok=True)
        return

    try:
        orig_mode = stat.S_IMODE(target.stat().st_mode)
    except FileNotFoundError:
        orig_mode = 0o644

    final_tmp = str(target) + ".pudo_new"
    Path(final_tmp).write_bytes(edited)
    os.chmod(final_tmp, orig_mode)
    os.rename(final_tmp, str(target))
    Path(tmp).unlink(missing_ok=True)

    audit(caller_name, "root", f"EDIT {filepath}", "OK")
    print(f"{_OK} Saved: {filepath}")


# =============================================================================
#  CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pudo",
        description=(
            "pudo — Privilege User DO  v" + VERSION + "\n"
            "More powerful than sudo: fine-grained Linux capabilities,\n"
            "HMAC-signed tokens, ambient cap inheritance, safe edit, full audit."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pudo id                                  # run as root
  pudo -u www-data stat /var/www           # run as another user
  pudo -g docker id                        # switch primary group
  pudo -C cap_net_raw,cap_net_admin id     # restricted capability set
  pudo -t 600 bash                         # 10-minute token, open bash
  pudo -n systemctl restart nginx          # non-interactive (token required)
  pudo -e /etc/hosts                       # safe privileged file edit
  pudo -l                                  # list your allowed commands
  pudo -k                                  # revoke session token
  pudo --shell                             # privileged shell
  pudo --log                               # last 100 audit entries (root only)
  pudo --show-caps                         # all capability names + numbers
""",
    )

    p.add_argument("-u", "--user",
                   default="root",
                   metavar="USER",
                   help="Run command as USER (default: root)")

    p.add_argument("-g", "--group",
                   default=None,
                   metavar="GROUP",
                   help="Set primary group to GROUP")

    # NOTE: -C (uppercase) for capability restriction — avoids clash with other flags
    p.add_argument("-C", "--capability",
                   default=None,
                   metavar="CAPS",
                   dest="cap_str",
                   help="Comma-separated capability list to restrict to "
                        "(e.g. cap_net_raw,cap_net_admin)")

    p.add_argument("-t", "--timeout",
                   type=int,
                   default=None,
                   metavar="SECONDS",
                   help=f"Session token TTL in seconds (default from pudo.conf)")

    p.add_argument("-n", "--non-interactive",
                   action="store_true",
                   help="Do not prompt for password — fail if no valid token")

    p.add_argument("-E", "--preserve-env",
                   action="store_true",
                   help="Preserve caller environment (dangerous variables still stripped)")

    p.add_argument("-e", "--edit",
                   metavar="FILE",
                   help="Safely edit FILE with privileges (like sudoedit)")

    p.add_argument("-l", "--list",
                   action="store_true",
                   help="List commands this user is allowed to run")

    p.add_argument("-k", "--revoke",
                   action="store_true",
                   help="Revoke current session token")

    p.add_argument("--shell",
                   action="store_true",
                   help="Open a privileged shell")

    p.add_argument("--login",
                   action="store_true",
                   help="Simulate a login shell (argv[0] prefixed with '-')")

    p.add_argument("--log",
                   action="store_true",
                   help="Print last 100 audit log entries (root only)")

    p.add_argument("--show-caps",
                   action="store_true",
                   help="List all recognised Linux capability names and numbers")

    p.add_argument("-v", "--version",
                   action="store_true",
                   help="Show version and exit")

    p.add_argument("command",
                   nargs=argparse.REMAINDER,
                   help="Command and arguments to execute")

    return p


# =============================================================================
#  Main
# =============================================================================

def main() -> int:
    global CFG
    CFG = _load_config()

    parser  = build_parser()
    args    = parser.parse_args()

    # strip leading '--' separator
    command_argv = list(args.command)
    if command_argv and command_argv[0] == "--":
        command_argv = command_argv[1:]

    # ── version ───────────────────────────────────────────────────────────────
    if args.version:
        print(f"pudo {VERSION}")
        return 0

    # ── show capability names ─────────────────────────────────────────────────
    if args.show_caps:
        print(f"\n{_C} Linux capabilities recognised by pudo:\n")
        print(f"  {'Bit':>4}  {'Name':<30}  Currently effective")
        print("  " + "─" * 60)
        active = set(read_current_caps())
        for name, bit in sorted(CAPS.items(), key=lambda x: x[1]):
            marker = "\033[1;32m ●\033[0m" if name in active else "  "
            print(f"  {bit:>4}  {name:<30} {marker}")
        print()
        return 0

    # ── audit log ─────────────────────────────────────────────────────────────
    if args.log:
        if os.getuid() != 0 and os.geteuid() != 0:
            sys.stderr.write(f"{_E} --log requires root.\n")
            return 1
        try:
            lines = AUDIT_LOG.read_text().splitlines()[-100:]
            for line in lines:
                print(line)
        except FileNotFoundError:
            print(f"{_W} Audit log not found: {AUDIT_LOG}")
        return 0

    # ── caller identity ───────────────────────────────────────────────────────
    caller_uid  = os.getuid()
    caller_euid = os.geteuid()

    try:
        caller_name = pwd.getpwuid(caller_uid).pw_name
    except KeyError:
        caller_name = str(caller_uid)

    # Must be running with effective root (via SUID wrapper)
    if caller_euid != 0:
        sys.stderr.write(
            f"{_E} pudo is not installed correctly.\n"
            f"  The C wrapper must be SUID root:\n"
            f"    sudo chown root:root /usr/local/bin/pudo\n"
            f"    sudo chmod 4755 /usr/local/bin/pudo\n"
        )
        return 1

    ttl   = args.timeout if args.timeout else CFG.get("token_timeout", DEFAULT_TOKEN_TTL)
    token = TokenStore(caller_uid, ttl)

    # ── revoke token ──────────────────────────────────────────────────────────
    if args.revoke:
        token.revoke()
        print(f"{_OK} pudo session token revoked.")
        return 0

    # ── list allowed commands ─────────────────────────────────────────────────
    if args.list:
        hostname = os.uname().nodename
        rules    = load_rules()
        groups   = _user_groups(caller_name)
        matches  = []
        for rule in rules:
            if rule.who == "ALL" or rule.who == caller_name:
                matches.append(rule)
            elif rule.who.startswith("%") and rule.who[1:] in groups:
                matches.append(rule)

        print(f"\n{_C} Rules for \033[1m{caller_name}\033[0m on {hostname}:\n")
        if not matches:
            print("  (no matching rules — check /etc/pudo/rules.d/)")
        for r in matches:
            flags = []
            if r.nopasswd:
                flags.append("NOPASSWD")
            if r.caps:
                flags.append(f"CAPS={','.join(r.caps)}")
            flag_str = "  " + "  ".join(flags) if flags else ""
            cmds = "  ".join(r.commands)
            print(f"  ({r.target_user}){flag_str}   {cmds}")
        print()
        return 0

    # ── secure edit ───────────────────────────────────────────────────────────
    if args.edit:
        try:
            authenticate(caller_name, token, args.non_interactive)
        except AccessDenied as e:
            sys.stderr.write(f"{_E} {e}\n")
            audit(caller_name, "root", f"EDIT {args.edit}", "DENIED")
            return 1
        try:
            secure_edit(args.edit, caller_name)
        except PudoError as e:
            sys.stderr.write(f"{_E} {e}\n")
            return 1
        return 0

    # ── need a command to run ─────────────────────────────────────────────────
    if not command_argv and not args.shell:
        parser.print_help()
        return 0

    target_user  = args.user
    target_group = args.group
    command_str  = " ".join(command_argv) if command_argv else "$SHELL"
    command_bin  = command_argv[0] if command_argv else (
        shutil.which(args.user) or args.user
    )

    # ── parse capability list ─────────────────────────────────────────────────
    cap_list: list[str] | None = None
    if args.cap_str:
        cap_list = [c.strip().lower() for c in args.cap_str.split(",") if c.strip()]
        for c in cap_list:
            if c not in CAPS:
                sys.stderr.write(f"{_E} Unknown capability: {c!r}\n"
                                 f"  Run 'pudo --show-caps' for the full list.\n")
                return 1

    # ── policy check ─────────────────────────────────────────────────────────
    hostname = os.uname().nodename
    rules    = load_rules()

    # root (caller_uid == 0) is always allowed
    if caller_uid == 0:
        matched = Rule("root", "ALL", "ALL", None, True, None, ["ALL"])
    else:
        matched = check_policy(caller_name, target_user, target_group,
                               command_bin, rules, hostname)

    if matched is None:
        sys.stderr.write(
            f"\n{_E} \033[1m{caller_name}\033[0m is not permitted to run "
            f"\033[1m{command_str}\033[0m as \033[1m{target_user}\033[0m "
            f"on this host.\n"
            f"  Add a rule to /etc/pudo/rules.d/local.rules\n\n"
        )
        audit(caller_name, target_user, command_str, "DENIED", cap_list)
        return 1

    # ── authentication ────────────────────────────────────────────────────────
    if not matched.nopasswd:
        try:
            authenticate(caller_name, token, args.non_interactive)
        except AccessDenied as e:
            sys.stderr.write(f"\n{_E} {e}\n\n")
            audit(caller_name, target_user, command_str, "AUTH_FAILED", cap_list)
            return 1

    # Rule may carry its own cap_list (if caller did not override with -C)
    if cap_list is None and matched.caps:
        cap_list = matched.caps

    # ── audit + exec ──────────────────────────────────────────────────────────
    audit(caller_name, target_user, command_str, "EXEC", cap_list)

    try:
        exec_privileged(
            target_user  = target_user,
            target_group = target_group,
            argv         = command_argv,
            cap_list     = cap_list,
            preserve_env = args.preserve_env,
            login_shell  = args.login or args.shell,
        )
    except PudoError as e:
        sys.stderr.write(f"\n{_E} {e}\n\n")
        audit(caller_name, target_user, command_str, f"FAIL:{e}", cap_list)
        return 1

    return 0  # unreachable after execve


if __name__ == "__main__":
    sys.exit(main())
