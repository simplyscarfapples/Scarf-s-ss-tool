"""
Minecraft SS String Logger - GUI (Windows)

Tabs:
  - Memory Scan:        scans a running process's memory for keyword strings
  - Recycle Bin:        reads $Recycle.Bin metadata for deleted-file history
  - Prefetch:           reads C:\\Windows\\Prefetch entries (program run history)
  - Process Timeline:   lists processes that started after a reference time
                         (e.g. after Minecraft launched)

Built for VISIBLE use during a screenshare the other person has agreed to.
Everything here reads artifacts already on disk or live process metadata;
nothing here captures keystrokes or runs hidden/in the background.
A match or entry is a lead to review, not proof of cheating.

Just run:  python mc_string_logger_gui.py
Missing dependencies (psutil) are installed automatically on first launch.
"""

import sys

if sys.platform != "win32":
    sys.exit("This tool only works on Windows.")

# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------
import importlib
import subprocess

REQUIRED = {"psutil": "psutil"}  # import name -> pip package name


def ensure_dependencies():
    missing = []
    for module, package in REQUIRED.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(package)
    if not missing:
        return
    print(f"[*] Installing missing dependencies: {', '.join(missing)}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *missing]
        )
        importlib.invalidate_caches()
    except Exception as exc:
        print(f"[!] Auto-install failed ({exc}). "
              f"Falling back to built-in methods; to fix, run: pip install {' '.join(missing)}")


ensure_dependencies()

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    sys.exit("tkinter is missing. Reinstall Python from python.org and make "
             "sure 'tcl/tk and IDLE' is checked.")

try:
    import psutil
except ImportError:
    psutil = None

import csv
import ctypes
import ctypes.wintypes as wt
import gzip
import hashlib
import json
import os
import queue
import re
import string
import struct
import threading
import winreg
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_KEYWORDS = [
    "killaura", "kill aura", "autoclicker", "auto clicker", "aimassist",
    "aim assist", "triggerbot", "scaffold", "xray", "x-ray", "bhop",
    "nofall", "antikb", "clickgui", "click gui", "wurst", "meteor client",
    "impact client", "liquidbounce", "vape", "rise client", "sigma client",
    "novoline", "astolfo", "doomsday", "dream client", "slinky",
]

MC_NAME_HINTS = ("javaw", "java", "minecraft", "lunarclient", "lunar", "badlion")

# ---------------------------------------------------------------------------
# WinAPI (used by the memory scan tab)
# ---------------------------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]

# --- Toolhelp32 bindings, used by the DLL / loaded-module scanner ----------
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wt.BOOL
kernel32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wt.BOOL


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


def filetime_to_datetime(ft):
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to datetime."""
    if not ft:
        return None
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NS = 10_000_000
    try:
        return datetime(1970, 1, 1) + timedelta(seconds=(ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NS)
    except (OverflowError, OSError, ValueError):
        return None


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


# ---------------------------------------------------------------------------
# Memory scan logic
# ---------------------------------------------------------------------------
def list_processes(name_filter):
    """Return list of (pid, name) whose name contains name_filter."""
    name_filter = name_filter.lower().strip()
    results = []
    if psutil:
        for p in psutil.process_iter(["pid", "name"]):
            n = p.info["name"] or ""
            if name_filter in n.lower():
                results.append((p.info["pid"], n))
    else:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True,
                             creationflags=0x08000000).stdout
        for row in csv.reader(out.splitlines()):
            if len(row) >= 2 and name_filter in row[0].lower():
                try:
                    results.append((int(row[1]), row[0]))
                except ValueError:
                    pass
    return sorted(results, key=lambda r: (r[1].lower(), r[0]))


def iter_regions(handle):
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    max_addr = 0x7FFFFFFFFFFF if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x7FFFFFFF
    while address < max_addr:
        res = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not res:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_NOACCESS)
                and not (mbi.Protect & PAGE_GUARD)):
            yield base, size
        address = base + size


def read_chunk(handle, base, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size,
                                    ctypes.byref(read))
    if not ok and read.value == 0:
        return b""
    return buf.raw[:read.value]


def scan_pid(pid, kw_regex, min_len, stop, q, dump_file):
    """Scan one process. Pushes ('hit', row) / ('progress', pct) onto q."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        q.put(("status", f"Could not open PID {pid} (error {ctypes.get_last_error()}). "
                         f"Try 'Run as admin'."))
        return 0, 0

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    max_chunk = 64 * 1024 * 1024
    seen_hits, seen_all = set(), set()
    total_strings = hits = 0

    try:
        regions = list(iter_regions(handle))
        total_bytes = sum(s for _, s in regions) or 1
        done_bytes = 0
        for base, size in regions:
            offset = 0
            while offset < size:
                if stop.is_set():
                    return total_strings, hits
                n = min(max_chunk, size - offset)
                data = read_chunk(handle, base + offset, n)
                chunk_base = base + offset
                offset += n
                done_bytes += n
                if not data:
                    continue
                found = [(m.start(), m.group().decode("ascii"), "ascii")
                         for m in ascii_re.finditer(data)]
                found += [(m.start(), m.group().decode("utf-16le"), "utf16")
                          for m in utf16_re.finditer(data)]
                for off, text, enc in found:
                    total_strings += 1
                    addr = chunk_base + off
                    if dump_file is not None and text not in seen_all:
                        seen_all.add(text)
                        dump_file.write(f"0x{addr:016X}\t{enc}\t{text}\n")
                    m = kw_regex.search(text) if kw_regex else None
                    if m:
                        kw = m.group(0).lower()
                        key = (kw, text)
                        if key in seen_hits:
                            continue
                        seen_hits.add(key)
                        hits += 1
                        q.put(("hit", (datetime.now().strftime("%H:%M:%S"), pid,
                                       f"0x{addr:016X}", enc, kw, text)))
                q.put(("progress", done_bytes * 100 / total_bytes))
    finally:
        kernel32.CloseHandle(handle)
    return total_strings, hits


# ---------------------------------------------------------------------------
# DLL / loaded-module scanning
# ---------------------------------------------------------------------------
def list_modules(pid):
    """Return [{'name','path','base','size'}, ...] for a process's loaded
    modules (DLLs + the main exe), or None if the snapshot couldn't be taken
    (process may need admin rights, or may have exited)."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == wt.HANDLE(-1).value:
        return None
    modules = []
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
    try:
        ok = kernel32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
            modules.append({
                "name": entry.szModule,
                "path": entry.szExePath,
                "base": base,
                "size": entry.modBaseSize,
            })
            ok = kernel32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return modules


def is_system_module_path(path):
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()
    return path.lower().startswith(windir)


def get_process_exe_dir(pid):
    if not psutil:
        return ""
    try:
        exe = psutil.Process(pid).exe()
        return os.path.dirname(exe)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Recycle Bin history
# ---------------------------------------------------------------------------
def list_drives():
    return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]


def parse_recycle_i_file(path):
    """Parse a $Recycle.Bin $I<hash> metadata file (Vista and newer)."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return None
    version = int.from_bytes(data[0:8], "little")
    file_size = int.from_bytes(data[8:16], "little")
    deleted_time = filetime_to_datetime(int.from_bytes(data[16:24], "little"))

    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        path_len = int.from_bytes(data[24:28], "little")
        raw = data[28:28 + path_len * 2]
    else:
        raw = data[24:]
    orig_path = raw.decode("utf-16le", errors="ignore").split("\x00")[0]
    if not orig_path:
        return None
    return {"deleted_time": deleted_time, "original_path": orig_path, "file_size": file_size}


def enumerate_recycle_bin(stop=None):
    """Yield dicts describing deleted files found in every drive's $Recycle.Bin."""
    results = []
    for drive in list_drives():
        if stop is not None and stop.is_set():
            break
        rb_path = os.path.join(drive, "$Recycle.Bin")
        if not os.path.isdir(rb_path):
            continue
        try:
            sid_dirs = os.listdir(rb_path)
        except (PermissionError, OSError):
            continue
        for sid in sid_dirs:
            sid_path = os.path.join(rb_path, sid)
            if not os.path.isdir(sid_path):
                continue
            try:
                files = os.listdir(sid_path)
            except (PermissionError, OSError):
                continue
            for fn in files:
                if not fn.startswith("$I"):
                    continue
                try:
                    parsed = parse_recycle_i_file(os.path.join(sid_path, fn))
                except Exception:
                    parsed = None
                if parsed:
                    parsed["drive"] = drive
                    parsed["sid"] = sid
                    results.append(parsed)
    results.sort(key=lambda r: r["deleted_time"] or datetime.min, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Prefetch history
# ---------------------------------------------------------------------------
PREFETCH_DIR = r"C:\Windows\Prefetch"
# Best-effort, version-specific offsets for the run-count field in UNCOMPRESSED
# prefetch files. These are not guaranteed accurate on every Windows build;
# Windows 10/11 prefetch files are MAM-compressed and are reported as such
# instead of being parsed.
RUN_COUNT_OFFSETS = {17: 0x90, 23: 0xD0, 26: 0xD0}


def try_parse_run_count(path, version):
    off = RUN_COUNT_OFFSETS.get(version)
    if off is None:
        return None
    try:
        with open(path, "rb") as f:
            f.seek(off)
            raw = f.read(4)
        if len(raw) == 4:
            return int.from_bytes(raw, "little")
    except Exception:
        pass
    return None


def enumerate_prefetch():
    results = []
    if not os.path.isdir(PREFETCH_DIR):
        return results
    try:
        entries = os.listdir(PREFETCH_DIR)
    except (PermissionError, OSError):
        return results
    for fn in entries:
        if not fn.lower().endswith(".pf"):
            continue
        path = os.path.join(PREFETCH_DIR, fn)
        try:
            st = os.stat(path)
        except OSError:
            continue
        name_part = fn[:-3]
        prog, _, hash_part = name_part.rpartition("-")
        if not prog:
            prog = name_part
        info = {
            "program": prog,
            "hash": hash_part,
            "created": datetime.fromtimestamp(st.st_ctime),
            "last_run_fs": datetime.fromtimestamp(st.st_mtime),
            "run_count": None,
            "compressed": False,
        }
        try:
            with open(path, "rb") as f:
                header = f.read(8)
            if header[:4] == b"MAM\x04":
                info["compressed"] = True
            else:
                version = int.from_bytes(header[0:4], "little")
                info["run_count"] = try_parse_run_count(path, version)
        except Exception:
            pass
        results.append(info)
    results.sort(key=lambda r: r["last_run_fs"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Process timeline
# ---------------------------------------------------------------------------
def find_reference_process_start():
    """Best-effort: earliest start time among processes that look Minecraft-related."""
    if not psutil:
        return None
    earliest = None
    for p in psutil.process_iter(["name", "create_time"]):
        n = (p.info["name"] or "").lower()
        if any(h in n for h in MC_NAME_HINTS):
            t = p.info["create_time"]
            if earliest is None or t < earliest:
                earliest = t
    return earliest


def list_java_candidates():
    """Return [(pid, name, create_time), ...] for running processes that look
    java/Minecraft-related, oldest first - the pool to pick a reference process from."""
    if not psutil:
        return []
    out = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        n = (p.info["name"] or "")
        nl = n.lower()
        if "java" in nl or any(h in nl for h in MC_NAME_HINTS):
            out.append((p.info["pid"], n, p.info["create_time"]))
    return sorted(out, key=lambda r: r[2])


def list_processes_since(ref_epoch):
    rows = []
    if not psutil or ref_epoch is None:
        return rows
    for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        t = p.info["create_time"]
        if t and t > ref_epoch:
            rows.append({
                "pid": p.info["pid"],
                "name": p.info["name"] or "-",
                "exe": p.info["exe"] or "-",
                "start": datetime.fromtimestamp(t),
                "delta": t - ref_epoch,
            })
    rows.sort(key=lambda r: r["start"])
    return rows


# ---------------------------------------------------------------------------
# Installed programs (registry Uninstall keys)
# ---------------------------------------------------------------------------
UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def _reg_value(key, name):
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value) if value is not None else ""
    except OSError:
        return ""


def _fmt_install_date(raw):
    if len(raw) == 8 and raw.isdigit():
        return f"{raw[:4]}-{raw[4:6]}-{raw[6:]}"
    return raw


def enumerate_installed_programs():
    """Read every Uninstall key (64-bit, 32-bit, and per-user). Stale keys left
    behind by uninstalled programs still show up here, which is the point."""
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, "All users (64-bit)", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, "All users (32-bit)", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, "Current user", 0),
    ]
    rows = []
    for hive, scope, flag in sources:
        try:
            root = winreg.OpenKey(hive, UNINSTALL_PATH, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        with root:
            count = winreg.QueryInfoKey(root)[0]
            for i in range(count):
                try:
                    sub_name = winreg.EnumKey(root, i)
                    with winreg.OpenKey(root, sub_name) as sub:
                        name = _reg_value(sub, "DisplayName")
                        if not name:
                            continue
                        rows.append({
                            "name": name,
                            "version": _reg_value(sub, "DisplayVersion"),
                            "publisher": _reg_value(sub, "Publisher"),
                            "install_date": _fmt_install_date(_reg_value(sub, "InstallDate")),
                            "location": _reg_value(sub, "InstallLocation"),
                            "key_modified": filetime_to_datetime(winreg.QueryInfoKey(sub)[2]),
                            "scope": scope,
                        })
                except OSError:
                    continue
    rows.sort(key=lambda r: r["name"].lower())
    return rows


# ---------------------------------------------------------------------------
# Hosts file check
# ---------------------------------------------------------------------------
HOSTS_PATH = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                          r"System32\drivers\etc\hosts")
LOOPBACK_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::", "127.0.0.2"}
HOSTS_WATCH_HINTS = ("mojang", "minecraft", "microsoft", "xboxlive", "xbox", "hypixel",
                     "anticheat", "anti-cheat", "easyanticheat", "battleye", "sentry",
                     "telemetry", "report", "verify", "auth")


def parse_hosts_file(path=HOSTS_PATH):
    """Returns {'rows': [...], 'error': str|None, 'modified': datetime|None, 'size': int}.
    Each row: line number, ip, host, kind, note. The stock hosts file has only
    comments, so any active entry beyond localhost is worth a look."""
    result = {"rows": [], "error": None, "modified": None, "size": 0}
    try:
        st = os.stat(path)
        result["modified"] = datetime.fromtimestamp(st.st_mtime)
        result["size"] = st.st_size
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        result["error"] = str(exc)
        return result

    for lineno, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, hosts = parts[0], parts[1:]
        for host in hosts:
            hl = host.lower()
            if hl == "localhost":
                kind = "default (localhost)"
            elif ip in LOOPBACK_IPS:
                kind = "blocks (points to loopback)"
            else:
                kind = "redirects to another IP"
            note = ""
            if kind != "default (localhost)" and any(h in hl for h in HOSTS_WATCH_HINTS):
                note = "Minecraft / anti-cheat / auth related name"
            result["rows"].append({"line": lineno, "ip": ip, "host": host,
                                   "kind": kind, "note": note})
    return result


# ---------------------------------------------------------------------------
# Shared client-root defaults, used by the Mods Scanner and Servers tabs.
# Points at each launcher's data folder (not a specific subfolder), since
# profile-based launchers (CurseForge, Modrinth App, Dawn, Prism/PolyMC/
# MultiMC, GDLauncher) keep a separate mods/servers.dat per instance rather
# than one global one - the actual folders get found by a bounded recursive
# search rather than a single hardcoded path.
# ---------------------------------------------------------------------------
CLIENT_ROOT_SUFFIXES = [
    ("Vanilla (.minecraft)", r".minecraft"),
    ("Lunar Client", r".lunarclient"),
    ("Badlion Client", r".badlion"),
    ("Feather Client", r".feather"),
    ("Dawn", r".dawn"),
    ("Modrinth App", r"ModrinthApp"),
    ("GDLauncher", r"gdlauncher_next"),
    ("Prism/PolyMC/MultiMC", r"PrismLauncher"),
]


def get_default_client_roots():
    appdata = os.environ.get("APPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")
    roots = []
    if appdata:
        roots += [(label, os.path.join(appdata, suffix)) for label, suffix in CLIENT_ROOT_SUFFIXES]
    if userprofile:
        roots.append(("CurseForge App", os.path.join(userprofile, r"curseforge\minecraft\Instances")))
    return roots


def _walk_with_depth_limit(root, max_depth):
    if not os.path.isdir(root):
        return
    root_depth = root.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip("\\/").count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        yield dirpath, dirnames, filenames


def find_dirs_named(root, name, max_depth=6):
    name_l = name.lower()
    return [dp for dp, _dn, _fn in _walk_with_depth_limit(root, max_depth)
            if os.path.basename(dp).lower() == name_l]


def find_files_named(root, filename, max_depth=6):
    name_l = filename.lower()
    found = []
    for dirpath, _dn, filenames in _walk_with_depth_limit(root, max_depth):
        for fn in filenames:
            if fn.lower() == name_l:
                found.append(os.path.join(dirpath, fn))
    return found


# ---------------------------------------------------------------------------
# Mods folder scanning (profile/instance-aware)
# ---------------------------------------------------------------------------
HASH_SIZE_CAP = 20 * 1024 * 1024  # skip hashing anything bigger than this


def find_mods_folders(root, max_depth=6):
    return find_dirs_named(root, "mods", max_depth)


def profile_label_for(found_dir, root):
    """Best-effort instance/profile name: the folder just above the found dir,
    falling back further up if that's the launcher root itself."""
    parent = os.path.dirname(found_dir)
    label = os.path.basename(parent)
    root_name = os.path.basename(root.rstrip("\\/"))
    if not label or label.lower() == root_name.lower():
        return "(default/global)"
    return label


def list_jars(mods_dir):
    results = []
    try:
        entries = os.listdir(mods_dir)
    except OSError:
        return results
    for fn in entries:
        if not fn.lower().endswith((".jar", ".jar.disabled")):
            continue
        path = os.path.join(mods_dir, fn)
        try:
            st = os.stat(path)
        except OSError:
            continue
        digest = ""
        try:
            if st.st_size <= HASH_SIZE_CAP:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                digest = h.hexdigest()
            else:
                digest = "(too large to hash)"
        except OSError:
            pass
        results.append({"file": fn, "path": path, "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime), "sha256": digest})
    return results


def scan_mods(roots, stop=None, progress_cb=None):
    """roots: [(label, path), ...]. Returns a flat list of jar rows, each
    tagged with which launcher and profile/instance it came from."""
    all_dirs = []
    for label, root in roots:
        for mdir in find_mods_folders(root):
            all_dirs.append((label, root, mdir))
    total = len(all_dirs) or 1
    rows = []
    for i, (label, root, mdir) in enumerate(all_dirs):
        if stop is not None and stop.is_set():
            break
        profile = profile_label_for(mdir, root)
        for jar in list_jars(mdir):
            jar["launcher"] = label
            jar["profile"] = profile
            jar["mods_dir"] = mdir
            rows.append(jar)
        if progress_cb:
            progress_cb((i + 1) * 100 / total)
    return rows


# ---------------------------------------------------------------------------
# Recent servers (servers.dat, NBT format)
# ---------------------------------------------------------------------------
class NBTReader:
    """Minimal big-endian NBT reader - just enough to pull server name/ip
    pairs out of a vanilla-format servers.dat file."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _read(self, n):
        b = self.data[self.pos:self.pos + n]
        if len(b) < n:
            raise ValueError("truncated NBT data")
        self.pos += n
        return b

    def read_byte(self):
        return struct.unpack(">b", self._read(1))[0]

    def read_short(self):
        return struct.unpack(">h", self._read(2))[0]

    def read_int(self):
        return struct.unpack(">i", self._read(4))[0]

    def read_long(self):
        return struct.unpack(">q", self._read(8))[0]

    def read_float(self):
        return struct.unpack(">f", self._read(4))[0]

    def read_double(self):
        return struct.unpack(">d", self._read(8))[0]

    def read_string(self):
        length = struct.unpack(">H", self._read(2))[0]
        return self._read(length).decode("utf-8", errors="replace")

    def read_payload(self, tag_type):
        if tag_type == 1:
            return self.read_byte()
        if tag_type == 2:
            return self.read_short()
        if tag_type == 3:
            return self.read_int()
        if tag_type == 4:
            return self.read_long()
        if tag_type == 5:
            return self.read_float()
        if tag_type == 6:
            return self.read_double()
        if tag_type == 7:
            n = self.read_int()
            return self._read(max(n, 0))
        if tag_type == 8:
            return self.read_string()
        if tag_type == 9:
            item_type = self.read_byte()
            n = self.read_int()
            if item_type == 0 or n <= 0:
                return []
            return [self.read_payload(item_type) for _ in range(n)]
        if tag_type == 10:
            compound = {}
            while True:
                t = self.read_byte()
                if t == 0:
                    break
                name = self.read_string()
                compound[name] = self.read_payload(t)
            return compound
        if tag_type == 11:
            n = self.read_int()
            return [self.read_int() for _ in range(max(n, 0))]
        if tag_type == 12:
            n = self.read_int()
            return [self.read_long() for _ in range(max(n, 0))]
        raise ValueError(f"unknown NBT tag type {tag_type}")

    def read_root(self):
        t = self.read_byte()
        if t == 0:
            return None
        self.read_string()  # root tag name, unused
        return self.read_payload(t)


def parse_nbt_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] == b"\x1f\x8b":  # some NBT files are gzip-compressed
        raw = gzip.decompress(raw)
    return NBTReader(raw).read_root()


def get_servers_from_file(path):
    try:
        root = parse_nbt_file(path)
    except Exception:
        return []
    if not isinstance(root, dict):
        return []
    out = []
    for s in root.get("servers", []) or []:
        if isinstance(s, dict):
            out.append({"name": s.get("name", ""), "ip": s.get("ip", "")})
    return out


def scan_servers(roots, max_depth=6):
    """roots: [(label, path), ...]. Returns rows: launcher, profile, name, ip, source file."""
    rows = []
    for label, root in roots:
        for dat_path in find_files_named(root, "servers.dat", max_depth):
            profile = profile_label_for(os.path.dirname(dat_path), root)
            for s in get_servers_from_file(dat_path):
                rows.append({"launcher": label, "profile": profile, "name": s["name"],
                            "ip": s["ip"], "source": dat_path})
    return rows


# ---------------------------------------------------------------------------
# Log Checker (usernames seen in chat/join-leave logs -> "possible alts")
# ---------------------------------------------------------------------------
NAME_BLACKLIST = {"server", "console", "you", "self", "unknown", "player", "steve", "alex"}

# (label, path relative to %APPDATA%) for clients that don't all keep logs
# under .minecraft\logs. Add more here as needed.
DEFAULT_LOG_PATH_SUFFIXES = [
    ("Vanilla (.minecraft)", r".minecraft\logs"),
    ("Lunar Client", r".lunarclient\logs"),
    ("Lunar Client (offline)", r".lunarclient\offline\multiver\logs"),
    ("Badlion Client", r".badlion\logs"),
    ("Feather Client", r".feather\logs"),
    ("Dawn (auto-sync)", r".dawn\auto-sync\groups\default\logs"),
]

LOG_LINE_PATTERNS = [
    re.compile(r"(?P<name>[A-Za-z0-9_]{3,16}) joined the game"),
    re.compile(r"(?P<name>[A-Za-z0-9_]{3,16}) left the game"),
    re.compile(r"<(?P<name>[A-Za-z0-9_]{3,16})>"),
    re.compile(r"UUID of player (?P<name>[A-Za-z0-9_]{3,16}) is"),
    re.compile(r"(?P<name>[A-Za-z0-9_]{3,16})\[/[\d.]+:\d+\] logged in"),
    re.compile(r"(?P<name>[A-Za-z0-9_]{3,16}) has (?:made the advancement|"
              r"completed the challenge|reached the goal)"),
]
TIME_PREFIX_RE = re.compile(r"\[(\d{2}:\d{2}:\d{2})\]")

# Minecraft (and most clients) print this once per session at startup - it's
# the account that actually launched the game, i.e. the PC owner, not someone
# they're talking to. Used to auto-tell "you" apart from other players in chat.
SETTING_USER_RE = re.compile(r"Setting user:\s*(?P<name>[A-Za-z0-9_]{3,16})")


def get_default_log_paths():
    """Return [(label, full_path), ...] built from %APPDATA% + known client subfolders."""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return []
    return [(label, os.path.join(appdata, suffix)) for label, suffix in DEFAULT_LOG_PATH_SUFFIXES]


def is_valid_username(name):
    return 3 <= len(name) <= 16 and name.lower() not in NAME_BLACKLIST


def extract_matches(line):
    """Return [(username, time_str), ...] found in one log line."""
    out = []
    for pat in LOG_LINE_PATTERNS:
        m = pat.search(line)
        if m:
            name = m.group("name")
            if is_valid_username(name):
                tm = TIME_PREFIX_RE.match(line)
                out.append((name, tm.group(1) if tm else ""))
    return out


def iter_log_files(root):
    if os.path.isfile(root):
        yield root
        return
    if not os.path.isdir(root):
        return
    for dirpath, _dirs, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".log") or fn.endswith(".log.gz"):
                yield os.path.join(dirpath, fn)


def read_log_lines(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
                return f.readlines()
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []


def scan_logs(paths, stop=None, progress_cb=None):
    """Scan every log file under the given paths.

    Returns (agg, local_names):
      agg: {username: {count, files, first_time, sample}} for every name seen
           joining, leaving, chatting, etc.
      local_names: usernames the log itself says launched the game session
                   (from "Setting user: ..." lines) - i.e. likely the PC
                   owner, not someone they were talking to.
    """
    agg = {}
    local_names = set()
    files = []
    for p in paths:
        files.extend(iter_log_files(p))
    total = len(files) or 1
    for i, path in enumerate(files):
        if stop is not None and stop.is_set():
            break
        for line in read_log_lines(path):
            su = SETTING_USER_RE.search(line)
            if su and is_valid_username(su.group("name")):
                local_names.add(su.group("name"))
            for name, t in extract_matches(line):
                entry = agg.setdefault(
                    name, {"count": 0, "files": set(), "first_time": t, "sample": line.strip()})
                entry["count"] += 1
                entry["files"].add(os.path.basename(path))
                if not entry["first_time"] and t:
                    entry["first_time"] = t
        if progress_cb:
            progress_cb((i + 1) * 100 / total)
    return agg, local_names


# ---------------------------------------------------------------------------
# Launcher account / profile scanning
# ---------------------------------------------------------------------------
# Only ever surface names/labels, never credentials. Any key that looks like
# it might hold a token, secret, or session value - or any value that's
# suspiciously long (tokens are long, usernames aren't) - is skipped.
ACCOUNT_NAME_KEYS = {"displayname", "username", "name", "profilename", "gamertag"}
SENSITIVE_KEY_HINTS = ("token", "secret", "password", "refresh", "session", "cookie",
                       "clientid", "uuid", "id")


def _is_sensitive(key, value):
    kl = key.lower()
    if any(h in kl for h in SENSITIVE_KEY_HINTS):
        return True
    if isinstance(value, str) and len(value) > 60:
        return True
    return False


def get_default_account_files():
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return []
    return [
        ("Vanilla launcher accounts", os.path.join(appdata, r".minecraft\launcher_accounts.json")),
        ("Vanilla launcher profiles (legacy)", os.path.join(appdata, r".minecraft\launcher_profiles.json")),
        ("Lunar Client accounts", os.path.join(appdata, r".lunarclient\settings\game\accounts.json")),
        ("TLauncher profiles", os.path.join(appdata, r".minecraft\TlauncherProfiles.json")),
    ]


def _walk_json_for_names(obj, names):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                _walk_json_for_names(v, names)
            elif isinstance(v, str) and v and k.lower() in ACCOUNT_NAME_KEYS and not _is_sensitive(k, v):
                names.add(v)
    elif isinstance(obj, list):
        for item in obj:
            _walk_json_for_names(item, names)


def scan_account_file(path):
    """Return the set of profile/display names found in one launcher JSON file.
    Never returns tokens, secrets, or other credential-shaped values."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return set()
    names = set()
    _walk_json_for_names(data, names)
    return names


def scan_account_files(paths):
    """Return {file_path: {names...}} for every readable file among paths."""
    result = {}
    for p in paths:
        if os.path.isfile(p):
            names = scan_account_file(p)
            if names:
                result[p] = names
    return result


# ---------------------------------------------------------------------------
# Memory Scan tab
# ---------------------------------------------------------------------------
class MemoryScanTab(ttk.Frame):
    COLUMNS = ("time", "pid", "address", "enc", "keyword", "string")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.rows = []
        self.proc_map = {}
        self._build_ui()
        self.refresh_processes()
        self.after(100, self._poll_queue)

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill="x")

        pf = ttk.LabelFrame(top, text="Target process", padding=8)
        pf.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(pf, text="Name contains:").grid(row=0, column=0, sticky="w")
        self.name_filter = tk.StringVar(value="javaw")
        ttk.Entry(pf, textvariable=self.name_filter, width=16).grid(row=0, column=1, padx=4)
        ttk.Button(pf, text="Refresh", command=self.refresh_processes).grid(row=0, column=2)
        ttk.Label(pf, text="Process:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.proc_var = tk.StringVar()
        self.proc_combo = ttk.Combobox(pf, textvariable=self.proc_var, width=32, state="readonly")
        self.proc_combo.grid(row=1, column=1, columnspan=2, sticky="we", pady=(6, 0), padx=4)
        self.scan_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(pf, text="Scan all matching processes", variable=self.scan_all
                        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

        of = ttk.LabelFrame(top, text="Options", padding=8)
        of.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(of, text="Min string length:").grid(row=0, column=0, sticky="w")
        self.min_len = tk.IntVar(value=5)
        ttk.Spinbox(of, from_=3, to=50, textvariable=self.min_len, width=5
                    ).grid(row=0, column=1, padx=4)
        self.dump_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Also save ALL strings to file", variable=self.dump_all
                        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        admin_text = "Running as admin" if is_admin() else "Not admin"
        ttk.Label(of, text=admin_text, foreground="green" if is_admin() else "gray"
                  ).grid(row=2, column=0, sticky="w", pady=(6, 0))
        if not is_admin():
            ttk.Button(of, text="Run as admin", command=self.run_admin
                       ).grid(row=2, column=1, pady=(6, 0))

        kf = ttk.LabelFrame(top, text="Keywords (one per line, case-insensitive)", padding=8)
        kf.pack(side="left", fill="both", expand=True)
        self.kw_text = tk.Text(kf, height=6, width=30)
        self.kw_text.pack(side="left", fill="both", expand=True)
        self.kw_text.insert("1.0", "\n".join(DEFAULT_KEYWORDS))
        kb = ttk.Frame(kf)
        kb.pack(side="left", fill="y", padx=(6, 0))
        ttk.Button(kb, text="Load...", command=self.load_keywords).pack(fill="x")
        ttk.Button(kb, text="Save...", command=self.save_keywords).pack(fill="x", pady=4)
        ttk.Button(kb, text="Reset", command=self.reset_keywords).pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.start_btn = ttk.Button(ctl, text="Start scan", command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctl, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left")
        ttk.Button(ctl, text="Clear", command=self.clear_results).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=25).pack(side="left")
        self.progress = ttk.Progressbar(ctl, length=220, maximum=100)
        self.progress.pack(side="right")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings", selectmode="browse")
        widths = {"time": 70, "pid": 60, "address": 140, "enc": 55, "keyword": 120, "string": 600}
        for c in self.COLUMNS:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "string"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)

        self.detail = tk.Text(self, height=4, wrap="word", state="disabled")
        self.detail.pack(fill="x", pady=(8, 0))
        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(4, 0))

    def refresh_processes(self):
        procs = list_processes(self.name_filter.get())
        self.proc_map = {f"{n} (PID {pid})": pid for pid, n in procs}
        labels = list(self.proc_map)
        self.proc_combo["values"] = labels
        if labels:
            self.proc_combo.current(0)
        else:
            self.proc_var.set("")
        self.status.set(f"Found {len(labels)} matching process(es).")

    def get_keywords(self):
        lines = self.kw_text.get("1.0", "end").splitlines()
        return [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]

    def load_keywords(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.kw_text.delete("1.0", "end")
                self.kw_text.insert("1.0", f.read())

    def save_keywords(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.get_keywords()))

    def reset_keywords(self):
        self.kw_text.delete("1.0", "end")
        self.kw_text.insert("1.0", "\n".join(DEFAULT_KEYWORDS))

    def run_admin(self):
        if messagebox.askyesno("Run as admin", "Restart this tool with administrator rights?"):
            relaunch_as_admin()
            self.winfo_toplevel().destroy()

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        if self.scan_all.get():
            pids = list(self.proc_map.values())
        else:
            pid = self.proc_map.get(self.proc_var.get())
            pids = [pid] if pid else []
        if not pids:
            messagebox.showwarning("No process", "No target process selected. "
                                   "Is Minecraft running? Try Refresh.")
            return
        keywords = self.get_keywords()
        if not keywords and not self.dump_all.get():
            messagebox.showwarning("No keywords", "Add at least one keyword.")
            return
        try:
            min_len = max(3, int(self.min_len.get()))
        except (ValueError, tk.TclError):
            min_len = 5
        kw_regex = (re.compile("|".join(re.escape(k) for k in keywords), re.IGNORECASE)
                    if keywords else None)

        self.stop_event.clear()
        self.progress["value"] = 0
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status.set(f"Scanning {len(pids)} process(es)...")

        self.worker = threading.Thread(
            target=self._worker, args=(pids, kw_regex, min_len, self.dump_all.get()),
            daemon=True)
        self.worker.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status.set("Stopping...")

    def _worker(self, pids, kw_regex, min_len, dump_all):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)
        dump_file = None
        if dump_all:
            dump_file = open(os.path.join(log_dir, f"allstrings_{stamp}.txt"), "w", encoding="utf-8")
        summary = []
        try:
            for pid in pids:
                if self.stop_event.is_set():
                    break
                self.q.put(("status", f"Scanning PID {pid}..."))
                total, hits = scan_pid(pid, kw_regex, min_len, self.stop_event, self.q, dump_file)
                summary.append(f"PID {pid}: {total} strings, {hits} matches")
        except Exception as exc:
            summary.append(f"Error: {exc}")
        finally:
            if dump_file:
                dump_file.close()
        self.q.put(("done", " | ".join(summary), stamp, log_dir))

    def _poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "hit":
                    self.rows.append(msg[1])
                    if self._row_matches_filter(msg[1]):
                        self._insert_row(msg[1])
                elif kind == "progress":
                    self.progress["value"] = msg[1]
                elif kind == "status":
                    self.status.set(msg[1])
                elif kind == "done":
                    self._finish(msg[1], msg[2], msg[3])
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _finish(self, summary, stamp, log_dir):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        log_path = os.path.join(log_dir, f"ss_log_{stamp}.txt")
        self._write_log(log_path)
        state = "Stopped" if self.stop_event.is_set() else "Done"
        self.status.set(f"{state}. {summary or 'No data.'}  Log saved: {log_path}")

    def _insert_row(self, row):
        time_, pid, addr, enc, kw, text = row
        self.tree.insert("", "end", values=(time_, pid, addr, enc, kw, text[:300]))

    def _row_matches_filter(self, row):
        f = self.filter_var.get().strip().lower()
        return not f or any(f in str(v).lower() for v in row)

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            if self._row_matches_filter(row):
                self._insert_row(row)

    def show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        visible = [r for r in self.rows if self._row_matches_filter(r)]
        if idx < len(visible):
            row = visible[idx]
            self.detail.config(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", f"{row[2]} [{row[3]}] kw='{row[4]}'\n{row[5]}")
            self.detail.config(state="disabled")

    def clear_results(self):
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0

    def _write_log(self, path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            if path.lower().endswith(".csv"):
                w = csv.writer(f)
                w.writerow(self.COLUMNS)
                w.writerows(self.rows)
            else:
                f.write(f"# SS string log - {datetime.now().isoformat()}\n")
                f.write("# Matches are leads to review, not proof of cheating.\n\n")
                for t, pid, addr, enc, kw, text in self.rows:
                    f.write(f"[{t}] PID {pid} {addr} [{enc}] kw='{kw}' :: {text}\n")

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text log", "*.txt"), ("CSV", "*.csv")])
        if path:
            self._write_log(path)
            self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# DLL Scanner tab
# ---------------------------------------------------------------------------
class DLLScannerTab(ttk.Frame):
    COLUMNS = ("name", "location", "base", "size", "path")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.rows = []
        self.proc_map = {}
        self._build_ui()
        self.refresh_processes()

    def _build_ui(self):
        note = ("Lists DLLs (and the main exe) currently loaded into a process - "
                "catches cheats injected as a module rather than run as their own "
                "visible program. \"Location\" just tells you whether the file sits "
                "under Windows' system folder or the game's own folder; anything "
                "else is worth a closer look, not automatic proof of anything.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        pf = ttk.LabelFrame(self, text="Target process", padding=8)
        pf.pack(fill="x", pady=(8, 0))
        ttk.Label(pf, text="Name contains:").grid(row=0, column=0, sticky="w")
        self.name_filter = tk.StringVar(value="javaw")
        ttk.Entry(pf, textvariable=self.name_filter, width=16).grid(row=0, column=1, padx=4)
        ttk.Button(pf, text="Refresh", command=self.refresh_processes).grid(row=0, column=2)
        ttk.Label(pf, text="Process:").grid(row=0, column=3, sticky="w", padx=(12, 0))
        self.proc_var = tk.StringVar()
        self.proc_combo = ttk.Combobox(pf, textvariable=self.proc_var, width=32, state="readonly")
        self.proc_combo.grid(row=0, column=4, sticky="we", padx=4)
        admin_text = "Running as admin" if is_admin() else "Not admin"
        ttk.Label(pf, text=admin_text, foreground="green" if is_admin() else "gray"
                  ).grid(row=0, column=5, padx=(12, 0))
        if not is_admin():
            ttk.Button(pf, text="Run as admin", command=self.run_admin).grid(row=0, column=6)

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan loaded modules", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=25).pack(side="left")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"name": 220, "location": 110, "base": 140, "size": 90, "path": 440}
        labels = {"name": "Module", "location": "Location", "base": "Base address",
                  "size": "Size (bytes)", "path": "Full path"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "path"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def refresh_processes(self):
        procs = list_processes(self.name_filter.get())
        self.proc_map = {f"{n} (PID {pid})": pid for pid, n in procs}
        labels = list(self.proc_map)
        self.proc_combo["values"] = labels
        if labels:
            self.proc_combo.current(0)
        else:
            self.proc_var.set("")
        self.status.set(f"Found {len(labels)} matching process(es).")

    def run_admin(self):
        if messagebox.askyesno("Run as admin", "Restart this tool with administrator rights?"):
            relaunch_as_admin()
            self.winfo_toplevel().destroy()

    def start_scan(self):
        pid = self.proc_map.get(self.proc_var.get())
        if not pid:
            messagebox.showwarning("No process", "No target process selected. Try Refresh.")
            return
        modules = list_modules(pid)
        if modules is None:
            messagebox.showerror(
                "Couldn't read modules",
                f"Could not snapshot modules for PID {pid} (error {ctypes.get_last_error()}). "
                f"Try 'Run as admin', or the process may have exited.")
            return
        game_dir = get_process_exe_dir(pid)
        self.rows = []
        for m in modules:
            if is_system_module_path(m["path"]):
                location = "system"
            elif game_dir and m["path"].lower().startswith(game_dir.lower()):
                location = "game folder"
            else:
                location = "other"
            self.rows.append({**m, "location": location})
        self.apply_filter()
        self.status.set(f"PID {pid}: {len(self.rows)} loaded module(s).")

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for m in self.rows:
            if f and f not in m["name"].lower() and f not in m["path"].lower() and f not in m["location"]:
                continue
            self.tree.insert("", "end", values=(
                m["name"], m["location"], f"0x{m['base']:016X}", m["size"], m["path"]))

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["module", "location", "base_address", "size_bytes", "path"])
            for m in self.rows:
                w.writerow([m["name"], m["location"], f"0x{m['base']:016X}", m["size"], m["path"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Recycle Bin tab
# ---------------------------------------------------------------------------
class RecycleBinTab(ttk.Frame):
    COLUMNS = ("deleted", "original_path", "size", "drive", "sid")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.rows = []
        self.stop_event = threading.Event()
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        note = ("Reads deleted-file metadata from each drive's $Recycle.Bin. "
                "Only the current Windows account's own recycle bin folder is "
                "reliably readable without admin rights.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan Recycle Bin", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=30).pack(side="left")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"deleted": 150, "original_path": 620, "size": 90, "drive": 60, "sid": 160}
        labels = {"deleted": "Deleted", "original_path": "Original path", "size": "Size (bytes)",
                  "drive": "Drive", "sid": "Account SID"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "original_path"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        self.scan_btn.config(state="disabled")
        self.status.set("Scanning $Recycle.Bin on all drives...")
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def _worker(self):
        try:
            rows = enumerate_recycle_bin(self.stop_event)
        except Exception as exc:
            rows = []
            self.after(0, lambda: messagebox.showerror("Recycle Bin scan failed", str(exc)))
        self.after(0, lambda: self._finish(rows))

    def _finish(self, rows):
        self.rows = rows
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(rows)} deleted-file record(s).")

    def _insert_row(self, r):
        self.tree.insert("", "end", values=(
            fmt_dt(r["deleted_time"]), r["original_path"], r["file_size"], r["drive"], r["sid"]))

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for r in self.rows:
            if not f or f in r["original_path"].lower():
                self._insert_row(r)

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["deleted_time", "original_path", "size_bytes", "drive", "sid"])
            for r in self.rows:
                w.writerow([fmt_dt(r["deleted_time"]), r["original_path"],
                           r["file_size"], r["drive"], r["sid"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Prefetch tab
# ---------------------------------------------------------------------------
class PrefetchTab(ttk.Frame):
    COLUMNS = ("program", "hash", "created", "last_run", "run_count", "compressed")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.rows = []
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        note = ("Reads C:\\Windows\\Prefetch for program run history. Needs admin "
                "rights to read, and only exists if prefetch is enabled. Windows 10/11 "
                "prefetch files are compressed; run count isn't parsed for those, only "
                "the program name and file-system timestamps are shown. \"Last run\" is "
                "the prefetch file's last-modified time, used as an approximation.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan Prefetch", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=30).pack(side="left")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"program": 260, "hash": 90, "created": 150, "last_run": 150,
                  "run_count": 90, "compressed": 90}
        labels = {"program": "Program", "hash": "Hash", "created": "First seen",
                  "last_run": "Last run (approx.)", "run_count": "Run count (approx.)",
                  "compressed": "Compressed"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "program"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        if not is_admin():
            messagebox.showwarning("Admin needed",
                                   "Reading the Prefetch folder usually needs admin rights. "
                                   "Restart as admin from the Memory Scan tab if this comes back empty.")
        self.scan_btn.config(state="disabled")
        self.status.set("Scanning Prefetch...")
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def _worker(self):
        try:
            rows = enumerate_prefetch()
        except Exception as exc:
            rows = []
            self.after(0, lambda: messagebox.showerror("Prefetch scan failed", str(exc)))
        self.after(0, lambda: self._finish(rows))

    def _finish(self, rows):
        self.rows = rows
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(rows)} prefetch entr{'y' if len(rows)==1 else 'ies'}.")

    def _insert_row(self, r):
        self.tree.insert("", "end", values=(
            r["program"], r["hash"], fmt_dt(r["created"]), fmt_dt(r["last_run_fs"]),
            r["run_count"] if r["run_count"] is not None else "-",
            "yes" if r["compressed"] else "no"))

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for r in self.rows:
            if not f or f in r["program"].lower():
                self._insert_row(r)

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["program", "hash", "first_seen", "last_run_approx",
                       "run_count_approx", "compressed"])
            for r in self.rows:
                w.writerow([r["program"], r["hash"], fmt_dt(r["created"]),
                           fmt_dt(r["last_run_fs"]), r["run_count"], r["compressed"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Mods Scanner tab
# ---------------------------------------------------------------------------
class ModsScannerTab(ttk.Frame):
    COLUMNS = ("launcher", "profile", "file", "size", "modified", "sha256")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.default_roots = get_default_client_roots()
        self.default_vars = {}
        self.custom_paths = []
        self.rows = []
        self.worker = None
        self.stop_event = threading.Event()
        self._build_ui()

    def _build_ui(self):
        note = ("Finds every \"mods\" folder under each launcher's data folder, "
                "including profile/instance-based launchers like CurseForge, "
                "Modrinth App, and Dawn where each instance keeps its own mods "
                "folder rather than one global one. Lists each jar with a SHA-256 "
                "hash (skipped for files over 20 MB) so you can compare against "
                "known-bad hashes if you keep a list.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        paths_frame = ttk.LabelFrame(self, text="Search locations", padding=8)
        paths_frame.pack(fill="x", pady=(8, 0))

        df = ttk.Frame(paths_frame)
        df.pack(fill="x")
        ttk.Label(df, text="Default launcher folders (unchecked ones weren't found):"
                  ).pack(anchor="w")
        for label, path in self.default_roots:
            exists = os.path.isdir(path)
            var = tk.BooleanVar(value=exists)
            text = f"{label}   ({path})" + ("" if exists else "   [not found]")
            ttk.Checkbutton(df, text=text, variable=var).pack(anchor="w")
            self.default_vars[label] = (var, path)

        cf = ttk.Frame(paths_frame)
        cf.pack(fill="x", pady=(10, 0))
        ttk.Label(cf, text="Custom launcher/instance folder:").pack(anchor="w")
        row = ttk.Frame(cf)
        row.pack(fill="x")
        self.custom_entry = tk.StringVar()
        ttk.Entry(row, textvariable=self.custom_entry, width=70).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse_path).pack(side="left", padx=4)
        ttk.Button(row, text="Add", command=self.add_custom_path).pack(side="left")
        self.custom_list = tk.Listbox(cf, height=3)
        self.custom_list.pack(fill="x", pady=(4, 0))
        ttk.Button(cf, text="Remove selected", command=self.remove_custom_path
                  ).pack(anchor="w", pady=(4, 0))

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan mods", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=25).pack(side="left")
        self.progress = ttk.Progressbar(ctl, length=200, maximum=100)
        self.progress.pack(side="right")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"launcher": 130, "profile": 150, "file": 220, "size": 90,
                  "modified": 140, "sha256": 280}
        labels = {"launcher": "Launcher", "profile": "Profile/instance", "file": "File",
                  "size": "Size (bytes)", "modified": "Modified", "sha256": "SHA-256"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "sha256"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.custom_entry.set(path)

    def add_custom_path(self):
        path = self.custom_entry.get().strip()
        if path and path not in self.custom_paths:
            self.custom_paths.append(path)
            self.custom_list.insert("end", path)
        self.custom_entry.set("")

    def remove_custom_path(self):
        for i in reversed(self.custom_list.curselection()):
            del self.custom_paths[i]
            self.custom_list.delete(i)

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        roots = [(label, path) for (label, (var, path)) in self.default_vars.items() if var.get()]
        roots += [("Custom", p) for p in self.custom_paths]
        if not roots:
            messagebox.showwarning("No locations", "Select at least one default folder or add a custom one.")
            return
        self.stop_event.clear()
        self.progress["value"] = 0
        self.scan_btn.config(state="disabled")
        self.status.set("Scanning for mods folders...")
        self.worker = threading.Thread(target=self._worker, args=(roots,), daemon=True)
        self.worker.start()

    def _worker(self, roots):
        def on_progress(pct):
            self.after(0, lambda: self.progress.configure(value=pct))
        try:
            rows = scan_mods(roots, self.stop_event, on_progress)
        except Exception as exc:
            rows = []
            self.after(0, lambda: messagebox.showerror("Mods scan failed", str(exc)))
        self.after(0, lambda: self._finish(rows))

    def _finish(self, rows):
        self.rows = rows
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(rows)} mod jar(s).")

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for m in self.rows:
            hay = f"{m['file']} {m['profile']} {m['launcher']}".lower()
            if f and f not in hay:
                continue
            self.tree.insert("", "end", values=(
                m["launcher"], m["profile"], m["file"], m["size"], fmt_dt(m["modified"]), m["sha256"]))

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["launcher", "profile", "file", "size_bytes", "modified", "sha256", "full_path"])
            for m in self.rows:
                w.writerow([m["launcher"], m["profile"], m["file"], m["size"],
                           fmt_dt(m["modified"]), m["sha256"], m["path"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Servers tab (recent/saved servers across launchers and profiles)
# ---------------------------------------------------------------------------
class ServersTab(ttk.Frame):
    COLUMNS = ("launcher", "profile", "name", "ip", "source")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.default_roots = get_default_client_roots()
        self.default_vars = {}
        self.custom_paths = []
        self.rows = []
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        note = ("Reads servers.dat (the multiplayer server list) from every "
                "launcher/instance folder found, including profile-based "
                "launchers where each instance keeps its own list.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        paths_frame = ttk.LabelFrame(self, text="Search locations", padding=8)
        paths_frame.pack(fill="x", pady=(8, 0))

        df = ttk.Frame(paths_frame)
        df.pack(fill="x")
        ttk.Label(df, text="Default launcher folders (unchecked ones weren't found):"
                  ).pack(anchor="w")
        for label, path in self.default_roots:
            exists = os.path.isdir(path)
            var = tk.BooleanVar(value=exists)
            text = f"{label}   ({path})" + ("" if exists else "   [not found]")
            ttk.Checkbutton(df, text=text, variable=var).pack(anchor="w")
            self.default_vars[label] = (var, path)

        cf = ttk.Frame(paths_frame)
        cf.pack(fill="x", pady=(10, 0))
        ttk.Label(cf, text="Custom launcher/instance folder:").pack(anchor="w")
        row = ttk.Frame(cf)
        row.pack(fill="x")
        self.custom_entry = tk.StringVar()
        ttk.Entry(row, textvariable=self.custom_entry, width=70).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse_path).pack(side="left", padx=4)
        ttk.Button(row, text="Add", command=self.add_custom_path).pack(side="left")
        self.custom_list = tk.Listbox(cf, height=3)
        self.custom_list.pack(fill="x", pady=(4, 0))
        ttk.Button(cf, text="Remove selected", command=self.remove_custom_path
                  ).pack(anchor="w", pady=(4, 0))

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan servers", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=25).pack(side="left")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"launcher": 130, "profile": 150, "name": 200, "ip": 200, "source": 320}
        labels = {"launcher": "Launcher", "profile": "Profile/instance", "name": "Server name",
                  "ip": "Address", "source": "Source file"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "source"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.custom_entry.set(path)

    def add_custom_path(self):
        path = self.custom_entry.get().strip()
        if path and path not in self.custom_paths:
            self.custom_paths.append(path)
            self.custom_list.insert("end", path)
        self.custom_entry.set("")

    def remove_custom_path(self):
        for i in reversed(self.custom_list.curselection()):
            del self.custom_paths[i]
            self.custom_list.delete(i)

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        roots = [(label, path) for (label, (var, path)) in self.default_vars.items() if var.get()]
        roots += [("Custom", p) for p in self.custom_paths]
        if not roots:
            messagebox.showwarning("No locations", "Select at least one default folder or add a custom one.")
            return
        self.scan_btn.config(state="disabled")
        self.status.set("Scanning for servers.dat files...")
        self.worker = threading.Thread(target=self._worker, args=(roots,), daemon=True)
        self.worker.start()

    def _worker(self, roots):
        try:
            rows = scan_servers(roots)
        except Exception as exc:
            rows = []
            self.after(0, lambda: messagebox.showerror("Server scan failed", str(exc)))
        self.after(0, lambda: self._finish(rows))

    def _finish(self, rows):
        self.rows = rows
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(rows)} saved server entr{'y' if len(rows)==1 else 'ies'}.")

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for r in self.rows:
            hay = f"{r['name']} {r['ip']} {r['profile']} {r['launcher']}".lower()
            if f and f not in hay:
                continue
            self.tree.insert("", "end", values=(
                r["launcher"], r["profile"], r["name"], r["ip"], r["source"]))

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["launcher", "profile", "server_name", "address", "source_file"])
            for r in self.rows:
                w.writerow([r["launcher"], r["profile"], r["name"], r["ip"], r["source"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Installed Programs tab
# ---------------------------------------------------------------------------
class InstalledProgramsTab(ttk.Frame):
    COLUMNS = ("name", "version", "publisher", "install_date", "key_modified", "scope", "location")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.rows = []
        self.sort_col = None
        self.sort_reverse = False
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        note = ("Reads the registry's list of installed programs (all users, 32-bit, "
                "and current user). Programs that were uninstalled sometimes leave "
                "their registry entry behind, so this can show software that's no "
                "longer on the PC. \"Key modified\" is when the entry was last "
                "written - click any column header to sort.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan installed programs", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=30).pack(side="left")

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"name": 260, "version": 100, "publisher": 170, "install_date": 100,
                  "key_modified": 140, "scope": 120, "location": 300}
        labels = {"name": "Name", "version": "Version", "publisher": "Publisher",
                  "install_date": "Install date", "key_modified": "Key modified",
                  "scope": "Scope", "location": "Install location"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c], command=lambda col=c: self.sort_by(col))
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "location"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        self.scan_btn.config(state="disabled")
        self.status.set("Reading installed programs from the registry...")
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def _worker(self):
        try:
            rows = enumerate_installed_programs()
        except Exception as exc:
            rows = []
            self.after(0, lambda: messagebox.showerror("Scan failed", str(exc)))
        self.after(0, lambda: self._finish(rows))

    def _finish(self, rows):
        self.rows = rows
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(rows)} installed program entr{'y' if len(rows)==1 else 'ies'}.")

    def _sort_key(self, r):
        if self.sort_col == "key_modified":
            return r["key_modified"] or datetime.min
        return str(r[self.sort_col]).lower()

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col, self.sort_reverse = col, (col == "key_modified")
        self.rows.sort(key=self._sort_key, reverse=self.sort_reverse)
        self.apply_filter()

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        for r in self.rows:
            hay = f"{r['name']} {r['publisher']} {r['location']}".lower()
            if f and f not in hay:
                continue
            self.tree.insert("", "end", values=(
                r["name"], r["version"], r["publisher"], r["install_date"],
                fmt_dt(r["key_modified"]), r["scope"], r["location"]))

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["name", "version", "publisher", "install_date", "key_modified",
                       "scope", "install_location"])
            for r in self.rows:
                w.writerow([r["name"], r["version"], r["publisher"], r["install_date"],
                           fmt_dt(r["key_modified"]), r["scope"], r["location"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Hosts Check tab
# ---------------------------------------------------------------------------
class HostsCheckTab(ttk.Frame):
    COLUMNS = ("line", "ip", "host", "kind", "note")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.rows = []
        self._build_ui()

    def _build_ui(self):
        note = ("Reads the Windows hosts file. A stock hosts file has only comments, "
                "so any active entry beyond localhost is worth a look. Entries that "
                "point a domain at 0.0.0.0 / 127.0.0.1 block it; entries pointing "
                "at another IP redirect it. Some cheat clients add entries to stop "
                "anti-cheat or report domains from loading - but plenty of "
                "legitimate software (ad blockers, dev tools) edits this file too, "
                "so check what a flagged entry actually is before reading into it.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        ttk.Button(ctl, text="Check hosts file", command=self.check).pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text=f"File: {HOSTS_PATH}", foreground="gray").pack(side="left", padx=(16, 0))

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"line": 60, "ip": 140, "host": 320, "kind": 200, "note": 300}
        labels = {"line": "Line", "ip": "IP", "host": "Hostname", "kind": "Type",
                  "note": "Note"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "note"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def check(self):
        result = parse_hosts_file()
        self.tree.delete(*self.tree.get_children())
        if result["error"]:
            self.rows = []
            self.status.set(f"Couldn't read the hosts file: {result['error']}")
            return
        self.rows = result["rows"]
        for r in self.rows:
            self.tree.insert("", "end", values=(r["line"], r["ip"], r["host"], r["kind"], r["note"]))
        extra = [r for r in self.rows if r["kind"] != "default (localhost)"]
        stamp = f"Last modified {fmt_dt(result['modified'])}, {result['size']} bytes."
        if extra:
            self.status.set(f"{len(extra)} active entr{'y' if len(extra)==1 else 'ies'} beyond "
                            f"localhost. {stamp}")
        else:
            self.status.set(f"No active entries beyond localhost - looks clean. {stamp}")

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", "Nothing to export yet. Run a check first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["line", "ip", "hostname", "type", "note"])
            for r in self.rows:
                w.writerow([r["line"], r["ip"], r["host"], r["kind"], r["note"]])
        self.status.set(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Process Timeline tab
# ---------------------------------------------------------------------------
class ProcessTimelineTab(ttk.Frame):
    COLUMNS = ("start", "delta", "pid", "name", "path")

    def __init__(self, parent):
        super().__init__(parent, padding=8)
        self.ref_epoch = None
        self.auto_job = None
        self._build_ui()

    def _build_ui(self):
        note = ("Lists processes that started after a reference time (e.g. when "
                "Minecraft launched). This only sees processes still running now "
                "and whatever starts from here on - Windows doesn't keep deep launch "
                "history by default.")
        ttk.Label(self, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        ctl = ttk.Frame(self)
        ctl.pack(fill="x", pady=(8, 0))
        ttk.Button(ctl, text="Auto-detect (earliest match)", command=self.use_mc_launch
                  ).pack(side="left")
        ttk.Button(ctl, text="Use now", command=self.use_now).pack(side="left", padx=6)
        self.ref_label = ttk.Label(ctl, text="Reference time: not set")
        self.ref_label.pack(side="left", padx=(12, 0))

        pf = ttk.LabelFrame(self, text="Or base it on a specific process (useful with multiple "
                                       "accounts/clients running)", padding=8)
        pf.pack(fill="x", pady=(8, 0))
        row = ttk.Frame(pf)
        row.pack(fill="x")
        self.java_var = tk.StringVar()
        self.java_combo = ttk.Combobox(row, textvariable=self.java_var, width=55, state="readonly")
        self.java_combo.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Refresh list", command=self.refresh_java_list).pack(side="left", padx=4)
        ttk.Button(row, text="Use selected", command=self.use_selected_java).pack(side="left")

        ctl2 = ttk.Frame(self)
        ctl2.pack(fill="x", pady=(6, 0))
        self.auto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctl2, text="Auto-refresh every", variable=self.auto_var,
                        command=self._toggle_auto).pack(side="left")
        self.interval = tk.IntVar(value=5)
        ttk.Spinbox(ctl2, from_=2, to=60, textvariable=self.interval, width=4
                   ).pack(side="left")
        ttk.Label(ctl2, text="sec").pack(side="left", padx=(2, 12))
        ttk.Button(ctl2, text="Refresh now", command=self.refresh).pack(side="left")
        ttk.Button(ctl2, text="Export...", command=self.export).pack(side="left", padx=6)

        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"start": 150, "delta": 90, "pid": 70, "name": 220, "path": 450}
        labels = {"start": "Started", "delta": "After ref. (s)", "pid": "PID",
                  "name": "Name", "path": "Path"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "path"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Set a reference time to begin.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

        self.java_proc_map = {}
        self.refresh_java_list()

    def refresh_java_list(self):
        if not psutil:
            self.status.set("psutil unavailable - can't list processes.")
            return
        cands = list_java_candidates()
        self.java_proc_map = {}
        labels = []
        for pid, name, ct in cands:
            label = f"{name}  (PID {pid})  started {datetime.fromtimestamp(ct).strftime('%H:%M:%S')}"
            self.java_proc_map[label] = (pid, ct)
            labels.append(label)
        self.java_combo["values"] = labels
        if labels:
            self.java_combo.current(0)
        else:
            self.java_var.set("")
        self.status.set(f"Found {len(labels)} java/client process(es) to choose from.")

    def use_selected_java(self):
        info = self.java_proc_map.get(self.java_var.get())
        if not info:
            messagebox.showwarning("No selection", "Pick a process from the list first "
                                   "(click Refresh list if it's empty).")
            return
        pid, ct = info
        self.ref_epoch = ct
        self.ref_label.config(
            text=f"Reference time: {fmt_dt(datetime.fromtimestamp(ct))} (PID {pid}, picked manually)")
        self.refresh()

    def use_mc_launch(self):
        if not psutil:
            messagebox.showerror("psutil missing", "psutil failed to install; can't read processes.")
            return
        t = find_reference_process_start()
        if t is None:
            messagebox.showinfo("Not found", "No running process matched "
                                "javaw / java / minecraft / lunar / badlion. "
                                "Launch Minecraft first, or use 'Use now' instead.")
            return
        self.ref_epoch = t
        self.ref_label.config(text=f"Reference time: {fmt_dt(datetime.fromtimestamp(t))} (Minecraft launch)")
        self.refresh()

    def use_now(self):
        self.ref_epoch = datetime.now().timestamp()
        self.ref_label.config(text=f"Reference time: {fmt_dt(datetime.fromtimestamp(self.ref_epoch))} (manual)")
        self.refresh()

    def refresh(self):
        if self.ref_epoch is None:
            self.status.set("Set a reference time first.")
            return
        rows = list_processes_since(self.ref_epoch)
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", values=(
                fmt_dt(r["start"]), f"{r['delta']:.1f}", r["pid"], r["name"], r["exe"]))
        self.status.set(f"{len(rows)} process(es) started after the reference time. "
                        f"Last refreshed {datetime.now().strftime('%H:%M:%S')}.")
        self._last_rows = rows

    def _toggle_auto(self):
        if self.auto_var.get():
            self._auto_tick()
        elif self.auto_job:
            self.after_cancel(self.auto_job)
            self.auto_job = None

    def _auto_tick(self):
        self.refresh()
        if self.auto_var.get():
            self.auto_job = self.after(max(2, self.interval.get()) * 1000, self._auto_tick)

    def export(self):
        rows = getattr(self, "_last_rows", [])
        if not rows:
            messagebox.showinfo("Export", "Nothing to export yet. Refresh first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["started", "seconds_after_reference", "pid", "name", "path"])
            for r in rows:
                w.writerow([fmt_dt(r["start"]), f"{r['delta']:.1f}", r["pid"], r["name"], r["exe"]])
        self.status.set(f"Exported {len(rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Log Checker tab
# ---------------------------------------------------------------------------
class LogCheckerTab(ttk.Frame):
    COLUMNS = ("username", "likely_you", "count", "files", "first_time", "sample")
    ACCOUNT_COLUMNS = ("source", "name")

    def __init__(self, parent):
        super().__init__(parent, padding=0)
        self.default_paths = get_default_log_paths()
        self.default_vars = {}  # label -> (BooleanVar, path)
        self.custom_paths = []
        self.results = {}
        self.local_names = set()
        self.worker = None
        self.stop_event = threading.Event()

        self.default_account_paths = get_default_account_files()
        self.account_default_vars = {}
        self.custom_account_paths = []
        self.account_results = {}
        self.account_worker = None

        self._build_scroll_container()
        self._build_log_section(self.body)
        self._build_accounts_section(self.body)

    def _build_scroll_container(self):
        self.scroll_canvas = tk.Canvas(self, highlightthickness=0)
        canvas = self.scroll_canvas
        vsb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.body = ttk.Frame(canvas, padding=8)
        self.body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.body, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        def on_wheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", on_wheel, add="+")

    def _build_log_section(self, root):
        note = ("Scans Minecraft-style log files for usernames seen joining, "
                "leaving, or chatting, and lists each unique one under Possible "
                "Alts below. This only reads log files already on disk. Your own "
                "username (from \"Setting user: ...\" lines) is auto-detected and "
                "excluded, so chat lines from you aren't mistaken for an alt.")
        ttk.Label(root, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        paths_frame = ttk.LabelFrame(root, text="Log locations", padding=8)
        paths_frame.pack(fill="x", pady=(8, 0))

        df = ttk.Frame(paths_frame)
        df.pack(fill="x")
        ttk.Label(df, text="Default paths (unchecked ones weren't found on this PC):"
                  ).pack(anchor="w")
        if not self.default_paths:
            ttk.Label(df, text="(%APPDATA% not available)", foreground="gray").pack(anchor="w")
        for label, path in self.default_paths:
            exists = os.path.isdir(path)
            var = tk.BooleanVar(value=exists)
            text = f"{label}   ({path})" + ("" if exists else "   [not found]")
            ttk.Checkbutton(df, text=text, variable=var).pack(anchor="w")
            self.default_vars[label] = (var, path)

        cf = ttk.Frame(paths_frame)
        cf.pack(fill="x", pady=(10, 0))
        ttk.Label(cf, text="Custom path (for clients that don't keep logs in .minecraft):"
                  ).pack(anchor="w")
        row = ttk.Frame(cf)
        row.pack(fill="x")
        self.custom_entry = tk.StringVar()
        ttk.Entry(row, textvariable=self.custom_entry, width=70).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse_path).pack(side="left", padx=4)
        ttk.Button(row, text="Add", command=self.add_custom_path).pack(side="left")
        self.custom_list = tk.Listbox(cf, height=4)
        self.custom_list.pack(fill="x", pady=(4, 0))
        ttk.Button(cf, text="Remove selected", command=self.remove_custom_path
                  ).pack(anchor="w", pady=(4, 0))

        ef = ttk.Frame(root)
        ef.pack(fill="x", pady=(8, 0))
        ttk.Label(ef, text="Also exclude (comma-separated - friends, teammates, etc.):"
                  ).pack(anchor="w")
        self.exclude_var = tk.StringVar()
        self.exclude_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ef, textvariable=self.exclude_var, width=60).pack(fill="x")
        self.auto_exclude_local = tk.BooleanVar(value=True)
        ttk.Checkbutton(ef, text="Auto-exclude detected local account name(s) - see below",
                        variable=self.auto_exclude_local,
                        command=self.apply_filter).pack(anchor="w", pady=(4, 0))
        self.local_names_label = ttk.Label(ef, text="Detected local account(s): none yet (scan first)",
                                           foreground="gray")
        self.local_names_label.pack(anchor="w")

        ctl = ttk.Frame(root)
        ctl.pack(fill="x", pady=(8, 0))
        self.scan_btn = ttk.Button(ctl, text="Scan logs", command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=25).pack(side="left")
        self.progress = ttk.Progressbar(ctl, length=200, maximum=100)
        self.progress.pack(side="right")

        mid = ttk.LabelFrame(root, text="Possible alts (other players seen in logs)", padding=4)
        mid.pack(fill="both", expand=True, pady=(8, 0))
        mid.configure(height=260)
        mid.pack_propagate(False)
        self.tree = ttk.Treeview(mid, columns=self.COLUMNS, show="headings")
        widths = {"username": 150, "likely_you": 80, "count": 80, "files": 200,
                  "first_time": 100, "sample": 360}
        labels = {"username": "Username", "likely_you": "Likely you?", "count": "Occurrences",
                  "files": "Seen in file(s)", "first_time": "First match time",
                  "sample": "Sample log line"}
        for c in self.COLUMNS:
            self.tree.heading(c, text=labels[c])
            self.tree.column(c, width=widths[c], anchor="w", stretch=(c == "sample"))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(root, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.custom_entry.set(path)

    def add_custom_path(self):
        path = self.custom_entry.get().strip()
        if path and path not in self.custom_paths:
            self.custom_paths.append(path)
            self.custom_list.insert("end", path)
        self.custom_entry.set("")

    def remove_custom_path(self):
        for i in reversed(self.custom_list.curselection()):
            del self.custom_paths[i]
            self.custom_list.delete(i)

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        paths = [path for (var, path) in self.default_vars.values() if var.get()]
        paths += list(self.custom_paths)
        if not paths:
            messagebox.showwarning("No paths", "Select at least one default path or add a custom one.")
            return
        self.stop_event.clear()
        self.progress["value"] = 0
        self.scan_btn.config(state="disabled")
        self.status.set("Scanning log files...")
        self.worker = threading.Thread(target=self._worker, args=(paths,), daemon=True)
        self.worker.start()

    def _worker(self, paths):
        def on_progress(pct):
            self.after(0, lambda: self.progress.configure(value=pct))
        try:
            agg, local_names = scan_logs(paths, self.stop_event, on_progress)
        except Exception as exc:
            agg, local_names = {}, set()
            self.after(0, lambda: messagebox.showerror("Log scan failed", str(exc)))
        self.after(0, lambda: self._finish(agg, local_names))

    def _finish(self, agg, local_names):
        self.results = agg
        self.local_names = local_names
        if local_names:
            self.local_names_label.config(
                text="Detected local account(s): " + ", ".join(sorted(local_names)),
                foreground="black")
        else:
            self.local_names_label.config(
                text="Detected local account(s): none found (no \"Setting user:\" line in these logs)",
                foreground="gray")
        self.apply_filter()
        self.scan_btn.config(state="normal")
        self.status.set(f"Found {len(agg)} unique username(s) across the scanned logs.")

    def _excluded_set(self):
        manual = {n.strip().lower() for n in self.exclude_var.get().split(",") if n.strip()}
        if self.auto_exclude_local.get():
            manual |= {n.lower() for n in self.local_names}
        return manual

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        f = self.filter_var.get().strip().lower()
        excluded = self._excluded_set()
        local_lower = {n.lower() for n in self.local_names}
        for name, info in sorted(self.results.items(), key=lambda kv: -kv[1]["count"]):
            if name.lower() in excluded:
                continue
            if f and f not in name.lower():
                continue
            likely_you = "yes" if name.lower() in local_lower else ""
            self.tree.insert("", "end", values=(
                name, likely_you, info["count"], ", ".join(sorted(info["files"])),
                info["first_time"], info["sample"][:200]))

    def export(self):
        if not self.results:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        excluded = self._excluded_set()
        local_lower = {n.lower() for n in self.local_names}
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["username", "likely_you", "occurrences", "files", "first_time", "sample_line"])
            for name, info in sorted(self.results.items(), key=lambda kv: -kv[1]["count"]):
                if name.lower() in excluded:
                    continue
                w.writerow([name, "yes" if name.lower() in local_lower else "",
                           info["count"], ", ".join(sorted(info["files"])),
                           info["first_time"], info["sample"]])
        self.status.set(f"Exported to {path}")

    # ---- Launcher accounts / profile names --------------------------------
    def _build_accounts_section(self, root):
        frame = ttk.LabelFrame(root, text="Launcher accounts / profile names", padding=8)
        frame.pack(fill="x", pady=(16, 0))

        note = ("Reads profile/display names out of launcher account files already "
                "on this PC - i.e. which accounts are logged into which launcher. "
                "Only names are shown; access tokens, passwords, and other "
                "credential-looking values are never read out, whatever the file "
                "contains.")
        ttk.Label(frame, text=note, wraplength=1000, foreground="gray").pack(fill="x")

        df = ttk.Frame(frame)
        df.pack(fill="x", pady=(8, 0))
        ttk.Label(df, text="Default launcher files (unchecked ones weren't found):"
                  ).pack(anchor="w")
        if not self.default_account_paths:
            ttk.Label(df, text="(%APPDATA% not available)", foreground="gray").pack(anchor="w")
        for label, path in self.default_account_paths:
            exists = os.path.isfile(path)
            var = tk.BooleanVar(value=exists)
            text = f"{label}   ({path})" + ("" if exists else "   [not found]")
            ttk.Checkbutton(df, text=text, variable=var).pack(anchor="w")
            self.account_default_vars[label] = (var, path)

        cf = ttk.Frame(frame)
        cf.pack(fill="x", pady=(10, 0))
        ttk.Label(cf, text="Custom account/profile file (e.g. another launcher's accounts.json):"
                  ).pack(anchor="w")
        row = ttk.Frame(cf)
        row.pack(fill="x")
        self.custom_account_entry = tk.StringVar()
        ttk.Entry(row, textvariable=self.custom_account_entry, width=70).pack(
            side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self.browse_account_file).pack(side="left", padx=4)
        ttk.Button(row, text="Add", command=self.add_custom_account_path).pack(side="left")
        self.custom_account_list = tk.Listbox(cf, height=3)
        self.custom_account_list.pack(fill="x", pady=(4, 0))
        ttk.Button(cf, text="Remove selected", command=self.remove_custom_account_path
                  ).pack(anchor="w", pady=(4, 0))

        ctl = ttk.Frame(frame)
        ctl.pack(fill="x", pady=(8, 0))
        self.account_scan_btn = ttk.Button(ctl, text="Scan accounts", command=self.start_account_scan)
        self.account_scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export_accounts).pack(side="left", padx=6)

        mid = ttk.Frame(frame)
        mid.pack(fill="both", pady=(8, 0))
        mid.configure(height=160)
        mid.pack_propagate(False)
        self.account_tree = ttk.Treeview(mid, columns=self.ACCOUNT_COLUMNS, show="headings")
        self.account_tree.heading("source", text="Launcher file")
        self.account_tree.heading("name", text="Profile / display name")
        self.account_tree.column("source", width=480, anchor="w")
        self.account_tree.column("name", width=260, anchor="w")
        asb = ttk.Scrollbar(mid, orient="vertical", command=self.account_tree.yview)
        self.account_tree.configure(yscrollcommand=asb.set)
        self.account_tree.pack(side="left", fill="both", expand=True)
        asb.pack(side="left", fill="y")

        self.account_status = tk.StringVar(value="Ready.")
        ttk.Label(frame, textvariable=self.account_status, anchor="w").pack(fill="x", pady=(8, 0))

    def browse_account_file(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All", "*.*")])
        if path:
            self.custom_account_entry.set(path)

    def add_custom_account_path(self):
        path = self.custom_account_entry.get().strip()
        if path and path not in self.custom_account_paths:
            self.custom_account_paths.append(path)
            self.custom_account_list.insert("end", path)
        self.custom_account_entry.set("")

    def remove_custom_account_path(self):
        for i in reversed(self.custom_account_list.curselection()):
            del self.custom_account_paths[i]
            self.custom_account_list.delete(i)

    def start_account_scan(self):
        if self.account_worker and self.account_worker.is_alive():
            return
        paths = [path for (var, path) in self.account_default_vars.values() if var.get()]
        paths += list(self.custom_account_paths)
        if not paths:
            messagebox.showwarning("No files", "Select at least one default file or add a custom one.")
            return
        self.account_scan_btn.config(state="disabled")
        self.account_status.set("Scanning launcher account files...")
        self.account_worker = threading.Thread(target=self._account_worker, args=(paths,), daemon=True)
        self.account_worker.start()

    def _account_worker(self, paths):
        try:
            result = scan_account_files(paths)
        except Exception as exc:
            result = {}
            self.after(0, lambda: messagebox.showerror("Account scan failed", str(exc)))
        self.after(0, lambda: self._account_finish(result))

    def _account_finish(self, result):
        self.account_results = result
        self.account_tree.delete(*self.account_tree.get_children())
        total_names = 0
        for path, names in result.items():
            for name in sorted(names):
                self.account_tree.insert("", "end", values=(path, name))
                total_names += 1
        self.account_scan_btn.config(state="normal")
        self.account_status.set(
            f"Found {total_names} profile name(s) across {len(result)} file(s).")

    def export_accounts(self):
        if not self.account_results:
            messagebox.showinfo("Export", "Nothing to export yet. Scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv"), ("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["source_file", "profile_name"])
            for source, names in self.account_results.items():
                for name in sorted(names):
                    w.writerow([source, name])
        self.account_status.set(f"Exported to {path}")


# ---------------------------------------------------------------------------
# Credits tab
# ---------------------------------------------------------------------------
class CreditsTab(ttk.Frame):
    NAMES = [
        "Scarf",
        "Zelz",
        "Clickbait",
        "that random guy that told me about the log idea",
        "the dead ghost of kizzer",
    ]

    def __init__(self, parent):
        super().__init__(parent, padding=24)
        ttk.Label(self, text="Scarf's SS Tool 1.0", font=("Segoe UI", 18, "bold")
                  ).pack(pady=(16, 4))
        ttk.Label(self, text="Credits", font=("Segoe UI", 13, "bold")).pack(pady=(24, 10))
        for name in self.NAMES:
            ttk.Label(self, text=name, font=("Segoe UI", 11)).pack(pady=2)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------
LIGHT_COLORS = dict(bg="#f0f0f0", fg="#000000", field_bg="#ffffff", select="#3399ff",
                    select_fg="#ffffff")
DARK_COLORS = dict(bg="#1e1e1e", fg="#e6e6e6", field_bg="#2b2b2b", select="#3a6ea5",
                   select_fg="#ffffff")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Scarf's SS Tool 1.0")
        self.geometry("1150x750")
        self.minsize(950, 600)

        self.style = ttk.Style(self)
        # Always use "clam" (not the native "vista" theme) for BOTH light and dark mode.
        # "vista" is natively drawn and only partially respects color overrides, which
        # is what caused light mode text/background to look broken after a theme switch.
        # "clam" honors every color we set, so both modes render consistently.
        self.light_theme = "clam"
        self.dark_mode = tk.BooleanVar(value=False)

        top = ttk.Frame(self)
        top.pack(fill="x")
        banner = ttk.Label(
            top,
            text=("Scarf's SS Tool 1.0 - for use during a screenshare the other person has "
                  "agreed to. Results are leads to review, not proof of cheating."),
            anchor="w", padding=4, foreground="#888")
        banner.pack(side="left", fill="x", expand=True)
        ttk.Checkbutton(top, text="Dark mode", variable=self.dark_mode,
                        command=self.toggle_dark_mode).pack(side="right", padx=8)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.scan_tab = MemoryScanTab(nb)
        self.dll_tab = DLLScannerTab(nb)
        self.log_tab = LogCheckerTab(nb)
        self.mods_tab = ModsScannerTab(nb)
        self.servers_tab = ServersTab(nb)
        self.recycle_tab = RecycleBinTab(nb)
        self.prefetch_tab = PrefetchTab(nb)
        self.programs_tab = InstalledProgramsTab(nb)
        self.hosts_tab = HostsCheckTab(nb)
        self.timeline_tab = ProcessTimelineTab(nb)
        self.credits_tab = CreditsTab(nb)

        nb.add(self.scan_tab, text="Memory Scan")
        nb.add(self.dll_tab, text="DLL Scanner")
        nb.add(self.log_tab, text="Log Checker")
        nb.add(self.mods_tab, text="Mods Scanner")
        nb.add(self.servers_tab, text="Servers")
        nb.add(self.recycle_tab, text="Recycle Bin")
        nb.add(self.prefetch_tab, text="Prefetch")
        nb.add(self.programs_tab, text="Installed Programs")
        nb.add(self.hosts_tab, text="Hosts Check")
        nb.add(self.timeline_tab, text="Process Timeline")
        nb.add(self.credits_tab, text="Credits")

        self._apply_theme(LIGHT_COLORS, self.light_theme)

        if psutil is None:
            messagebox.showwarning(
                "psutil unavailable",
                "psutil could not be installed automatically. The Memory Scan and "
                "Recycle Bin tabs still work; Process Timeline needs psutil - "
                "install manually with: pip install psutil")

    def toggle_dark_mode(self):
        if self.dark_mode.get():
            self._apply_theme(DARK_COLORS, "clam")
        else:
            self._apply_theme(LIGHT_COLORS, self.light_theme)

    def _apply_theme(self, c, theme_name):
        s = self.style
        s.theme_use(theme_name)
        s.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field_bg"])
        for name in ("TFrame", "TLabel", "TLabelframe", "TLabelframe.Label",
                    "TCheckbutton", "TNotebook"):
            s.configure(name, background=c["bg"], foreground=c["fg"])
        s.map("TCheckbutton", background=[("active", c["bg"])])
        s.configure("TButton", background=c["field_bg"], foreground=c["fg"])
        s.map("TButton", background=[("active", c["select"])])
        s.configure("TEntry", fieldbackground=c["field_bg"], foreground=c["fg"])
        s.configure("TSpinbox", fieldbackground=c["field_bg"], foreground=c["fg"])
        s.configure("TCombobox", fieldbackground=c["field_bg"], foreground=c["fg"],
                   background=c["field_bg"])
        s.map("TCombobox", fieldbackground=[("readonly", c["field_bg"])],
             foreground=[("readonly", c["fg"])])
        s.configure("TNotebook.Tab", background=c["field_bg"], foreground=c["fg"])
        s.map("TNotebook.Tab", background=[("selected", c["select"])],
             foreground=[("selected", c["select_fg"])])
        s.configure("Treeview", background=c["field_bg"], fieldbackground=c["field_bg"],
                   foreground=c["fg"])
        s.configure("Treeview.Heading", background=c["bg"], foreground=c["fg"])
        s.map("Treeview", background=[("selected", c["select"])],
             foreground=[("selected", c["select_fg"])])
        s.configure("Horizontal.TProgressbar", background=c["select"])

        self.configure(bg=c["bg"])
        self._recolor_classic_widgets(c)

    def _recolor_classic_widgets(self, c):
        """ttk styles don't cover classic tk widgets (Text/Listbox/Canvas) - do those by hand."""
        text_like = [self.scan_tab.kw_text, self.scan_tab.detail]
        list_like = [self.log_tab.custom_list, self.log_tab.custom_account_list,
                    self.mods_tab.custom_list, self.servers_tab.custom_list]
        canvases = [self.log_tab.scroll_canvas]
        for w in text_like + list_like:
            try:
                w.configure(bg=c["field_bg"], fg=c["fg"], insertbackground=c["fg"],
                           selectbackground=c["select"], selectforeground=c["select_fg"],
                           highlightthickness=0)
            except tk.TclError:
                pass
        for w in canvases:
            try:
                w.configure(bg=c["bg"])
            except tk.TclError:
                pass


if __name__ == "__main__":
    App().mainloop()