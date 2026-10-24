"""
Scarf's SS Tool - Minecraft screenshare helper GUI (Windows)

Tabs:
  - Memory Scan:        scans a running process's memory for keyword strings
  - DLL Scanner:        lists DLLs loaded into a process
  - Log Checker:        usernames seen in logs (possible alts) + launcher accounts
  - Mods Scanner:       finds mods folders and hashes jars
  - Servers:            saved servers from servers.dat
  - Recycle Bin:        reads $Recycle.Bin metadata for deleted-file history
  - Prefetch:           reads C:\\Windows\\Prefetch (program run history, incl. Win10/11)
  - Installed Programs: registry uninstall entries, including leftovers
  - Hosts Check:        active entries in the hosts file
  - Process Timeline:   lists processes that started after a reference time

Built for VISIBLE use during a screenshare the other person has agreed to.
Everything here reads artifacts already on disk or live process metadata;
nothing here captures keystrokes or runs hidden/in the background.
A match or entry is a lead to review, not proof of cheating.

Just run: python Scarf_SS_tool.py
Missing dependencies (psutil) are installed automatically on first launch.

Code layout: backend scanners first, then the GUI. Every table tab is built on
the TableTab / ScanTab base classes - see the "GUI" section for how to add one.
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
import zipfile
from datetime import datetime

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
# Keywords come in two tiers so a reviewer can tell a strong lead from noise:
#   high     distinctive cheat module / client names that rarely appear by accident
#   context  ordinary words that also show up in innocent software (Gradle
#            "scaffold", the Scaffolding block, resource packs, anime skins...),
#            so a hit only means "read the surrounding string before concluding".
# In the keyword box, a line starting with "?" is a context keyword; anything
# else is high.
CONTEXT_PREFIX = "?"
HIGH_KEYWORDS = [
    "killaura", "kill aura", "autoclicker", "auto clicker", "aimassist",
    "aim assist", "triggerbot", "nofall", "antikb", "clickgui", "click gui",
    "wurst", "meteor client", "impact client", "liquidbounce", "rise client",
    "sigma client", "novoline", "dream client",
]
CONTEXT_KEYWORDS = [
    "scaffold", "xray", "x-ray", "bhop", "vape", "slinky", "astolfo", "doomsday",
]
# Editable lines as shown in the keyword box.
DEFAULT_KEYWORDS = HIGH_KEYWORDS + [CONTEXT_PREFIX + k for k in CONTEXT_KEYWORDS]

SEVERITY_RANK = {"": 0, "context": 1, "high": 2}


def parse_keyword_lines(lines):
    """['killaura', '?scaffold', '# note'] -> {'killaura': 'high', 'scaffold': 'context'}.
    If a word is listed in both tiers, high wins."""
    tiers = {}
    for raw in lines:
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        tier = "high"
        if line.startswith(CONTEXT_PREFIX):
            tier, line = "context", line[len(CONTEXT_PREFIX):].strip()
        if line and tiers.get(line) != "high":
            tiers[line] = tier
    return tiers


def keyword_lines(tiers):
    """Inverse of parse_keyword_lines (high first, then '?'-prefixed context ones)."""
    high = sorted(k for k, t in tiers.items() if t == "high")
    ctx = sorted(CONTEXT_PREFIX + k for k, t in tiers.items() if t != "high")
    return high + ctx


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
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01, UTC) to a local datetime."""
    if not ft:
        return None
    EPOCH_AS_FILETIME = 116444736000000000
    HUNDREDS_OF_NS = 10_000_000
    try:
        # fromtimestamp() gives local time, matching every other timestamp in the tool
        return datetime.fromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NS)
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

# Windows 10/11 compress every .pf file ("MAM" header, XPRESS-Huffman payload).
# We decompress them with ntdll's RtlDecompressBufferEx - the same routine
# Windows itself uses - then parse the normal "SCCA" prefetch format inside.
MAM_SIGNATURE = b"MAM\x04"
COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004
MAX_PF_UNCOMPRESSED = 64 * 1024 * 1024        # sanity cap; real files are < 1 MB

# SCCA format version -> human-readable Windows release
PF_VERSIONS = {17: "XP/2003", 23: "Vista/7", 26: "8/8.1", 30: "10", 31: "11"}

# Offsets of the "last run time" FILETIME array inside the decompressed file,
# and how many slots it has (Win8+ keeps the 8 most recent runs).
PF_RUN_TIMES = {17: (120, 1), 23: (128, 1), 26: (128, 8), 30: (128, 8), 31: (128, 8)}

# Candidate offsets of the run-count field. Windows 10 ships two slightly
# different layouts, so for those we try both and keep whichever is consistent
# with the run-time array (see _pick_run_count).
PF_RUN_COUNT_OFFSETS = {17: (144,), 23: (152,), 26: (208,), 30: (208, 200), 31: (208, 200)}

_ntdll = None


def _get_ntdll():
    """Load ntdll once and declare the two compression routines we use."""
    global _ntdll
    if _ntdll is None:
        nt = ctypes.WinDLL("ntdll")
        nt.RtlGetCompressionWorkSpaceSize.argtypes = [
            wt.USHORT, ctypes.POINTER(wt.ULONG), ctypes.POINTER(wt.ULONG)]
        nt.RtlGetCompressionWorkSpaceSize.restype = ctypes.c_long
        nt.RtlDecompressBufferEx.argtypes = [
            wt.USHORT, ctypes.c_void_p, wt.ULONG, ctypes.c_void_p, wt.ULONG,
            ctypes.POINTER(wt.ULONG), ctypes.c_void_p]
        nt.RtlDecompressBufferEx.restype = ctypes.c_long
        _ntdll = nt
    return _ntdll


def decompress_mam(raw):
    """Decompress a Windows 10/11 prefetch file (MAM header) to plain SCCA bytes.
    Raises ValueError / OSError if the data can't be decompressed."""
    if raw[:4] != MAM_SIGNATURE or len(raw) < 8:
        raise ValueError("not a MAM-compressed file")
    out_size = int.from_bytes(raw[4:8], "little")
    if not 0 < out_size <= MAX_PF_UNCOMPRESSED:
        raise ValueError(f"implausible uncompressed size ({out_size})")
    payload = raw[8:]
    nt = _get_ntdll()

    work_compress, work_fragment = wt.ULONG(0), wt.ULONG(0)
    status = nt.RtlGetCompressionWorkSpaceSize(
        COMPRESSION_FORMAT_XPRESS_HUFF, ctypes.byref(work_compress), ctypes.byref(work_fragment))
    if status != 0:
        raise OSError(f"RtlGetCompressionWorkSpaceSize failed (NTSTATUS 0x{status & 0xFFFFFFFF:08X})")

    workspace = ctypes.create_string_buffer(max(work_fragment.value, 1))
    src = ctypes.create_string_buffer(bytes(payload), len(payload))
    dst = ctypes.create_string_buffer(out_size)
    final = wt.ULONG(0)
    status = nt.RtlDecompressBufferEx(
        COMPRESSION_FORMAT_XPRESS_HUFF, dst, out_size, src, len(payload),
        ctypes.byref(final), workspace)
    if status != 0:
        raise OSError(f"RtlDecompressBufferEx failed (NTSTATUS 0x{status & 0xFFFFFFFF:08X})")
    return dst.raw[:final.value]


def _u32(data, off):
    return int.from_bytes(data[off:off + 4], "little")


def _u64(data, off):
    return int.from_bytes(data[off:off + 8], "little")


def _pick_run_count(data, version, nonzero_times):
    """Read the run count. The run-time array holds min(count, 8) non-zero
    entries, so when a version has more than one candidate offset we keep the
    one whose value agrees with that."""
    candidates = []
    for off in PF_RUN_COUNT_OFFSETS.get(version, ()):
        if off + 4 <= len(data):
            candidates.append(_u32(data, off))
    plausible = [c for c in candidates if 0 < c <= 1_000_000]
    for c in plausible:
        if min(c, 8) == nonzero_times:
            return c
    return plausible[0] if plausible else None


def parse_prefetch_bytes(data):
    """Parse the contents of one .pf file (compressed or not).

    Returns a dict: version, exe_name, run_count (or None), run_times (datetimes,
    newest first). Pure Python apart from the decompression step, so the
    parsing itself can be unit-tested anywhere. Raises ValueError for anything
    that isn't a prefetch file."""
    if data[:4] == MAM_SIGNATURE:
        data = decompress_mam(data)
    if len(data) < 84 or data[4:8] != b"SCCA":
        raise ValueError("missing SCCA signature")

    version = _u32(data, 0)
    if version not in PF_RUN_TIMES:
        raise ValueError(f"unsupported prefetch format version {version}")

    exe_name = data[16:76].decode("utf-16le", errors="ignore").split("\x00")[0]

    times_off, slots = PF_RUN_TIMES[version]
    run_times = []
    for i in range(slots):
        off = times_off + i * 8
        if off + 8 > len(data):
            break
        dt = filetime_to_datetime(_u64(data, off))
        if dt:
            run_times.append(dt)
    run_times.sort(reverse=True)

    return {
        "version": version,
        "exe_name": exe_name,
        "run_times": run_times,
        "run_count": _pick_run_count(data, version, len(run_times)),
    }


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
            "last_run_fs": datetime.fromtimestamp(st.st_mtime),   # fallback only
            "last_run": None,       # exact, from inside the file
            "run_times": [],        # up to 8 most recent runs, newest first
            "run_count": None,
            "version": None,
            "parsed": False,
            "error": "",
        }
        try:
            with open(path, "rb") as f:
                parsed = parse_prefetch_bytes(f.read())
            info["version"] = parsed["version"]
            info["run_times"] = parsed["run_times"]
            info["last_run"] = parsed["run_times"][0] if parsed["run_times"] else None
            info["run_count"] = parsed["run_count"]
            info["parsed"] = True
        except Exception as exc:
            info["error"] = str(exc)
        results.append(info)
    results.sort(key=lambda r: r["last_run"] or r["last_run_fs"], reverse=True)
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
# Specific names: a substring match is fine ("api.mojang.com", "easyanticheat.net").
HOSTS_WATCH_HINTS = ("mojang", "minecraft", "microsoft", "xboxlive", "xbox", "hypixel",
                     "anticheat", "anti-cheat", "easyanticheat", "battleye")
# Generic words: only count when they are a whole dot/hyphen-separated label, so
# "auth.example.com" matches but "oauth.example.com" / "author.blog" do not.
HOSTS_WEAK_HINTS = {"sentry", "telemetry", "report", "reports", "verify", "auth"}


def hosts_note_for(host):
    hl = host.lower()
    if any(h in hl for h in HOSTS_WATCH_HINTS):
        return "Minecraft / anti-cheat / auth related name"
    if HOSTS_WEAK_HINTS & set(re.split(r"[.\-_]", hl)):
        return "Generic auth/reporting-style name (weak match)"
    return ""


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
            note = hosts_note_for(host) if kind != "default (localhost)" else ""
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


# Big folders that never contain a mods folder or servers.dat. Skipping them
# keeps the search fast on installs with large worlds / asset caches.
HEAVY_DIRS = {"assets", "libraries", "saves", "runtime", "cache", "logs", "crash-reports",
              "screenshots", "resourcepacks", "shaderpacks", "backups", "datapacks",
              "node_modules", ".git", "versions"}


def _walk_with_depth_limit(root, max_depth, prune=()):
    if not os.path.isdir(root):
        return
    root_depth = root.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.rstrip("\\/").count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        elif prune:
            dirnames[:] = [d for d in dirnames if d.lower() not in prune]
        yield dirpath, dirnames, filenames


def find_dirs_named(root, name, max_depth=6):
    name_l = name.lower()
    prune = HEAVY_DIRS - {name_l}
    return [dp for dp, _dn, _fn in _walk_with_depth_limit(root, max_depth, prune)
            if os.path.basename(dp).lower() == name_l]


def find_files_named(root, filename, max_depth=6):
    name_l = filename.lower()
    found = []
    for dirpath, _dn, filenames in _walk_with_depth_limit(root, max_depth, HEAVY_DIRS):
        for fn in filenames:
            if fn.lower() == name_l:
                found.append(os.path.join(dirpath, fn))
    return found


# ---------------------------------------------------------------------------
# Mods folder scanning (profile/instance-aware)
# ---------------------------------------------------------------------------
HASH_SIZE_CAP = 20 * 1024 * 1024      # mod jars bigger than this aren't hashed
VERSION_HASH_CAP = 64 * 1024 * 1024   # game-version jars are bigger, allow more
JAR_SUFFIXES = (".jar", ".jar.disabled")
MODS_SUBFOLDER_DEPTH = 1              # also look in mods\<mc version>\ (Forge style)
MAX_FLAG_WORDS = 6                    # keep the Flags column readable

_SEP_RE = re.compile(r"[ _\-]+")


def _norm(text):
    """Lower-case and drop spaces/underscores/hyphens, so the keyword 'kill aura'
    or 'x-ray' also matches a class called KillAura or X_Ray."""
    return _SEP_RE.sub("", text.lower())


def build_keyword_matcher(tiers):
    """tiers: {keyword: 'high'|'context'} -> [(normalised, (keyword, tier)), ...]."""
    best = {}
    for kw, tier in tiers.items():
        key = _norm(kw)
        if key and (key not in best or tier == "high"):
            best[key] = (kw, tier)
    return list(best.items())


def worst_tier(hits):
    return max(hits.values(), key=lambda t: SEVERITY_RANK[t], default="")


def format_flags(hits):
    """{'killaura':'high','scaffold':'context'} -> 'HIGH: killaura | context: scaffold'."""
    parts = []
    for tier, label in (("high", "HIGH"), ("context", "context")):
        words = sorted(k for k, t in hits.items() if t == tier)
        if words:
            more = f" +{len(words) - MAX_FLAG_WORDS}" if len(words) > MAX_FLAG_WORDS else ""
            parts.append(f"{label}: {', '.join(words[:MAX_FLAG_WORDS])}{more}")
    return " | ".join(parts)


def _json_loads(raw):
    try:
        return json.loads(raw.decode("utf-8-sig", errors="ignore"), strict=False)
    except ValueError:
        return None


_TOML_NAME_RE = re.compile(r"^\s*displayName\s*=\s*[\"']([^\"']+)[\"']", re.M)
_TOML_ID_RE = re.compile(r"^\s*modId\s*=\s*[\"']([^\"']+)[\"']", re.M)


def _read_member(zf, name, limit=256 * 1024):
    try:
        with zf.open(name) as f:
            return f.read(limit)
    except Exception:
        return b""


def read_jar_mod_names(zf, names):
    """Mod name(s) the jar declares about itself (Fabric, Quilt, Forge/NeoForge).
    Handy for spotting a jar whose file name says one thing and whose contents say another."""
    lookup = {n.lower(): n for n in names}
    found = []

    raw = lookup.get("fabric.mod.json")
    if raw:
        data = _json_loads(_read_member(zf, raw))
        if isinstance(data, dict):
            found.append(data.get("name") or data.get("id"))

    raw = lookup.get("quilt.mod.json")
    if raw:
        data = _json_loads(_read_member(zf, raw))
        loader = data.get("quilt_loader") if isinstance(data, dict) else None
        if isinstance(loader, dict):
            meta = loader.get("metadata")
            found.append((meta.get("name") if isinstance(meta, dict) else None) or loader.get("id"))

    raw = lookup.get("mcmod.info")
    if raw:
        data = _json_loads(_read_member(zf, raw))
        if isinstance(data, dict):
            data = data.get("modList") or data.get("modlist")
        if isinstance(data, list):
            for item in data[:5]:
                if isinstance(item, dict):
                    found.append(item.get("name") or item.get("modid"))

    for toml in ("meta-inf/mods.toml", "meta-inf/neoforge.mods.toml"):
        raw = lookup.get(toml)
        if raw:
            text = _read_member(zf, raw).decode("utf-8", errors="ignore")
            m = _TOML_NAME_RE.search(text) or _TOML_ID_RE.search(text)
            if m:
                found.append(m.group(1))

    seen, out = set(), []
    for n in found:
        if isinstance(n, str) and n.strip() and n not in seen:
            seen.add(n)
            out.append(n.strip())
    return out


def inspect_jar(path, matcher, extra_text=()):
    """Open a jar and report its declared mod name plus any keyword hits found in
    entry names (class/package/resource paths), its file name, or its declared name.
    Returns {'info', 'hits': {kw: tier}, 'evidence': str, 'note': str}."""
    result = {"info": "", "hits": {}, "evidence": "", "note": ""}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            result["info"] = ", ".join(read_jar_mod_names(zf, names)[:3])
    except Exception:
        result["note"] = "not a readable jar/zip"
        names = []
    candidates = list(names) + [os.path.basename(path), result["info"], *extra_text]
    blob = _norm("\x00".join(c for c in candidates if c))
    hits = {kw: tier for key, (kw, tier) in matcher if key in blob}
    result["hits"] = hits
    evidence = []
    for kw in sorted(hits, key=lambda k: (-SEVERITY_RANK[hits[k]], k)):
        key = _norm(kw)
        for cand in candidates:
            if cand and key in _norm(cand):
                evidence.append(f"{kw}: {cand}")
                break
        if len(evidence) >= 3:
            break
    result["evidence"] = "; ".join(evidence)
    return result


def _sha256_of(path, size, cap):
    if size > cap:
        return "(too large to hash)"
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def describe_jar(path, shown_name, matcher, kind="mod", hash_cap=HASH_SIZE_CAP, extra_text=()):
    try:
        st = os.stat(path)
    except OSError:
        return None
    info = inspect_jar(path, matcher, extra_text)
    return {"kind": kind, "file": shown_name, "path": path, "size": st.st_size,
            "modified": datetime.fromtimestamp(st.st_mtime),
            "sha256": _sha256_of(path, st.st_size, hash_cap),
            "info": info["info"] or info["note"],
            "flags": format_flags(info["hits"]), "severity": worst_tier(info["hits"]),
            "evidence": info["evidence"]}


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


def list_jars(mods_dir, matcher=(), subfolder_depth=MODS_SUBFOLDER_DEPTH):
    """Every .jar / .jar.disabled in a mods folder, including one level of
    subfolders (mods\\1.12.2\\foo.jar). Each row is a describe_jar() dict."""
    results = []
    pending = [(mods_dir, 0)]
    while pending:
        folder, depth = pending.pop(0)
        try:
            entries = sorted(os.listdir(folder))
        except OSError:
            continue
        for fn in entries:
            path = os.path.join(folder, fn)
            if os.path.isdir(path):
                if depth < subfolder_depth:
                    pending.append((path, depth + 1))
                continue
            if not fn.lower().endswith(JAR_SUFFIXES):
                continue
            row = describe_jar(path, os.path.relpath(path, mods_dir), matcher)
            if row:
                results.append(row)
    return results


def list_versions(versions_dir, matcher=()):
    """One row per installed game version (versions\\<name>\\). Custom clients
    often install as their own version, so the folder name, its jar contents and
    its json's mainClass are all worth a look."""
    results = []
    try:
        entries = sorted(os.listdir(versions_dir))
    except OSError:
        return results
    for name in entries:
        folder = os.path.join(versions_dir, name)
        if not os.path.isdir(folder):
            continue
        meta = _json_loads(_read_file_head(os.path.join(folder, name + ".json")))
        bits = []
        if isinstance(meta, dict):
            if meta.get("inheritsFrom"):
                bits.append(f"inherits {meta['inheritsFrom']}")
            if meta.get("mainClass"):
                bits.append(str(meta["mainClass"]))
        extra = [name, *bits]
        jar = os.path.join(folder, name + ".jar")
        if os.path.isfile(jar):
            row = describe_jar(jar, name, matcher, kind="version",
                               hash_cap=VERSION_HASH_CAP, extra_text=extra)
            if row:
                if bits:
                    row["info"] = "; ".join(filter(None, [row["info"], *bits]))
                results.append(row)
            continue
        # json-only version (e.g. a Fabric/Forge profile that reuses the vanilla jar)
        text = _norm("\x00".join(extra))
        hits = {kw: tier for key, (kw, tier) in matcher if key in text}
        try:
            mtime = datetime.fromtimestamp(os.stat(folder).st_mtime)
        except OSError:
            mtime = datetime.min
        results.append({"kind": "version", "file": name, "path": folder, "size": 0,
                        "modified": mtime, "sha256": "", "info": "; ".join(bits) or "(no jar)",
                        "flags": format_flags(hits), "severity": worst_tier(hits),
                        "evidence": "; ".join(f"{k}: {name}" for k in sorted(hits))[:200]})
    return results


def _read_file_head(path, limit=256 * 1024):
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def scan_mods(roots, tiers=None, include_versions=True, stop=None, progress_cb=None):
    """roots: [(label, path), ...]; tiers: {keyword: 'high'|'context'}.
    Returns a flat list of rows, flagged ones first, each tagged with its
    launcher and profile/instance."""
    matcher = build_keyword_matcher(tiers or {})
    jobs = []
    for label, root in roots:
        for mdir in find_mods_folders(root):
            jobs.append(("mods", label, root, mdir))
        if include_versions:
            for vdir in find_dirs_named(root, "versions"):
                jobs.append(("versions", label, root, vdir))
    total = len(jobs) or 1
    rows = []
    for i, (kind, label, root, folder) in enumerate(jobs):
        if stop is not None and stop.is_set():
            break
        profile = profile_label_for(folder, root)
        found = list_jars(folder, matcher) if kind == "mods" else list_versions(folder, matcher)
        for row in found:
            row["launcher"] = label
            row["profile"] = profile
            row["mods_dir"] = folder
            rows.append(row)
        if progress_cb:
            progress_cb((i + 1) * 100 / total)
    rows.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], r["launcher"].lower(),
                             r["profile"].lower(), r["kind"], r["file"].lower()))
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
    # Chat only, so stack-trace tokens like <init> / <clinit> aren't read as players.
    # Handles "[CHAT] <Name>", "[CHAT] [Not Secure] <Name>" and singleplayer "INFO]: <Name>".
    re.compile(r"(?:\[CHAT\]|INFO\]:)\s*(?:\[[^\]<]*\]\s*)*<(?P<name>[A-Za-z0-9_]{3,16})>"),
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
    """Return the usernames found in one log line."""
    out = []
    for pat in LOG_LINE_PATTERNS:
        m = pat.search(line)
        if m and is_valid_username(m.group("name")):
            out.append(m.group("name"))
    return out


LOG_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def _safe_mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def log_file_date(path):
    """'YYYY-MM-DD' for a log file: from its name (2025-03-01-2.log.gz), otherwise
    from its modified time (latest.log and client-specific names)."""
    m = LOG_DATE_RE.match(os.path.basename(path))
    if m:
        return m.group(1)
    mt = _safe_mtime(path)
    return datetime.fromtimestamp(mt).strftime("%Y-%m-%d") if mt else ""


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
    """Scan every log file under the given paths, oldest first.

    Returns (agg, local_accounts):
      agg: {username: {count, files, first_time, sample}} for every name seen
           joining, leaving, chatting, etc. ("first_time" is 'YYYY-MM-DD HH:MM:SS').
      local_accounts: {username: {sessions, files, first_seen, last_seen}} for
           every account the logs say launched the game ("Setting user: ..."
           lines). These are the accounts used on THIS PC, so more than one name
           here is the strongest alt signal the logs offer.
    """
    agg, local_accounts = {}, {}
    files = set()
    for p in paths:
        files.update(iter_log_files(p))
    files = sorted(files, key=lambda f: (log_file_date(f), _safe_mtime(f)))
    total = len(files) or 1
    for i, path in enumerate(files):
        if stop is not None and stop.is_set():
            break
        day = log_file_date(path)
        base = os.path.basename(path)
        for line in read_log_lines(path):
            tm = TIME_PREFIX_RE.match(line)
            stamp = f"{day} {tm.group(1)}".strip() if tm else day
            su = SETTING_USER_RE.search(line)
            if su and is_valid_username(su.group("name")):
                acct = local_accounts.setdefault(
                    su.group("name"),
                    {"sessions": 0, "files": set(), "first_seen": stamp, "last_seen": stamp})
                acct["sessions"] += 1
                acct["files"].add(base)
                acct["last_seen"] = stamp      # files are processed oldest-first
            for name in extract_matches(line):
                entry = agg.setdefault(
                    name, {"count": 0, "files": set(), "first_time": stamp,
                           "sample": line.strip()})
                entry["count"] += 1
                entry["files"].add(base)
        if progress_cb:
            progress_cb((i + 1) * 100 / total)
    return agg, local_accounts


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
    if isinstance(value, str) and (len(value) > 60 or "@" in value):
        return True      # long = token-shaped; "@" = an email address, not a player name
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
    Never returns tokens, secrets, e-mail addresses or other credential-shaped values.

    launcher_accounts.json and launcher_profiles.json get dedicated handling because
    their generic "username" / "name" keys are an e-mail address and a version
    profile name respectively - neither is a player name."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return set()
    names = set()
    base = os.path.basename(path).lower()

    def add(value):
        if isinstance(value, str) and value and not _is_sensitive("name", value):
            names.add(value)

    if base == "launcher_accounts.json" and isinstance(data, dict):
        accounts = data.get("accounts")
        for acct in (accounts.values() if isinstance(accounts, dict) else []):
            profile = acct.get("minecraftProfile") if isinstance(acct, dict) else None
            if isinstance(profile, dict):
                add(profile.get("name"))
    elif base == "launcher_profiles.json" and isinstance(data, dict):
        db = data.get("authenticationDatabase")
        for acct in (db.values() if isinstance(db, dict) else []):
            if isinstance(acct, dict):
                add(acct.get("displayName"))
    else:
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


# ===========================================================================
# GUI
# ===========================================================================
#
# Layout of this section:
#   1. Small shared helpers (CSV export, admin prompt, plural text)
#   2. Reusable widgets: PathPicker, ProcessPicker
#   3. Base classes:  TableTab  ->  ScanTab
#   4. The tabs themselves (most are ~20-40 lines because the base classes do
#      the UI building, background threading, filtering and exporting)
#   5. App window + theming
# ===========================================================================

CSV_TYPES = [("CSV", "*.csv"), ("Text", "*.txt")]


def ask_csv_path():
    return filedialog.asksaveasfilename(defaultextension=".csv", filetypes=CSV_TYPES)


def write_csv(path, header, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def offer_admin_restart(widget):
    if messagebox.askyesno("Run as admin", "Restart this tool with administrator rights?"):
        relaunch_as_admin()
        widget.winfo_toplevel().destroy()


def admin_status_label(parent):
    """'Running as admin' / 'Not admin' label."""
    ok = is_admin()
    return ttk.Label(parent, text="Running as admin" if ok else "Not admin",
                     foreground="green" if ok else "gray")


# ---------------------------------------------------------------------------
# Reusable widgets
# ---------------------------------------------------------------------------
class PathPicker(ttk.Frame):
    """Checkboxes for default folders/files (unchecked if they don't exist) plus
    a user-managed list of custom ones.

    selected() -> [(label, path), ...]   custom entries are labelled "Custom".
    """

    def __init__(self, parent, defaults, default_caption, custom_caption,
                 files=False, list_height=3, empty_text=None):
        super().__init__(parent)
        self.files = files
        self.custom_paths = []
        self.default_vars = {}          # label -> (BooleanVar, path)
        exists = os.path.isfile if files else os.path.isdir

        df = ttk.Frame(self)
        df.pack(fill="x")
        ttk.Label(df, text=default_caption).pack(anchor="w")
        if not defaults and empty_text:
            ttk.Label(df, text=empty_text, foreground="gray").pack(anchor="w")
        for label, path in defaults:
            found = exists(path)
            var = tk.BooleanVar(value=found)
            text = f"{label}   ({path})" + ("" if found else "   [not found]")
            ttk.Checkbutton(df, text=text, variable=var).pack(anchor="w")
            self.default_vars[label] = (var, path)

        cf = ttk.Frame(self)
        cf.pack(fill="x", pady=(10, 0))
        ttk.Label(cf, text=custom_caption).pack(anchor="w")
        row = ttk.Frame(cf)
        row.pack(fill="x")
        self.entry_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.entry_var, width=70).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse...", command=self._browse).pack(side="left", padx=4)
        ttk.Button(row, text="Add", command=self._add).pack(side="left")
        self.listbox = tk.Listbox(cf, height=list_height)
        self.listbox.pack(fill="x", pady=(4, 0))
        ttk.Button(cf, text="Remove selected", command=self._remove).pack(anchor="w", pady=(4, 0))

    def _browse(self):
        if self.files:
            path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All", "*.*")])
        else:
            path = filedialog.askdirectory()
        if path:
            self.entry_var.set(path)

    def _add(self):
        path = self.entry_var.get().strip()
        if path and path not in self.custom_paths:
            self.custom_paths.append(path)
            self.listbox.insert("end", path)
        self.entry_var.set("")

    def _remove(self):
        for i in reversed(self.listbox.curselection()):
            del self.custom_paths[i]
            self.listbox.delete(i)

    def selected(self):
        picked = [(label, path) for label, (var, path) in self.default_vars.items() if var.get()]
        return picked + [("Custom", p) for p in self.custom_paths]


def add_path_picker(parent, title, **kwargs):
    """PathPicker inside a titled LabelFrame, packed into `parent`."""
    box = ttk.LabelFrame(parent, text=title, padding=8)
    box.pack(fill="x", pady=(8, 0))
    picker = PathPicker(box, **kwargs)
    picker.pack(fill="x")
    return picker


class ProcessPicker(ttk.LabelFrame):
    """'Target process' box: name filter + Refresh + a dropdown of matches.

    selected_pid() -> int | None      all_pids() -> [int, ...]
    """

    def __init__(self, parent, status_cb=None, default_filter="javaw",
                 scan_all_option=False, show_admin=False):
        super().__init__(parent, text="Target process", padding=8)
        self.status_cb = status_cb
        self.proc_map = {}
        self.scan_all = tk.BooleanVar(value=False)

        ttk.Label(self, text="Name contains:").grid(row=0, column=0, sticky="w")
        self.name_filter = tk.StringVar(value=default_filter)
        ttk.Entry(self, textvariable=self.name_filter, width=16).grid(row=0, column=1, padx=4)
        ttk.Button(self, text="Refresh", command=self.refresh).grid(row=0, column=2)
        ttk.Label(self, text="Process:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.proc_var = tk.StringVar()
        self.combo = ttk.Combobox(self, textvariable=self.proc_var, width=32, state="readonly")
        self.combo.grid(row=1, column=1, columnspan=2, sticky="we", pady=(6, 0), padx=4)
        if scan_all_option:
            ttk.Checkbutton(self, text="Scan all matching processes", variable=self.scan_all
                            ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        if show_admin:
            admin_status_label(self).grid(row=2, column=0, sticky="w", pady=(6, 0))
            if not is_admin():
                ttk.Button(self, text="Run as admin", command=lambda: offer_admin_restart(self)
                           ).grid(row=2, column=1, columnspan=2, sticky="w", pady=(6, 0), padx=4)

    def refresh(self):
        procs = list_processes(self.name_filter.get())
        self.proc_map = {f"{n} (PID {pid})": pid for pid, n in procs}
        labels = list(self.proc_map)
        self.combo["values"] = labels
        if labels:
            self.combo.current(0)
        else:
            self.proc_var.set("")
        if self.status_cb:
            self.status_cb(f"Found {len(labels)} matching process(es).")

    def selected_pid(self):
        return self.proc_map.get(self.proc_var.get())

    def all_pids(self):
        return list(self.proc_map.values())


# ---------------------------------------------------------------------------
# Base class 1: TableTab  - note, control bar, table, status line, CSV export
# ---------------------------------------------------------------------------
class TableTab(ttk.Frame):
    """Skeleton shared by every results-table tab.

    Subclasses describe the tab with class attributes and fill in hooks:

        NOTE            grey help text shown at the top
        COLUMNS         ((key, heading, width), ...)
        STRETCH         key of the column that absorbs extra width
        SEARCH_KEYS     row-dict keys the Filter box searches
        SORTABLE        True -> clicking a heading sorts (see sort_key)
        EXPORT_HEADER   CSV header row
        READY_TEXT      initial status line

        build_top()             widgets between the note and the control bar
        build_controls(ctl)     extra buttons in the control bar
        row_values(row)         tuple of cell values for the table
        export_row(row)         list of CSV cells for one row
        init_state() / after_build()   run before / after the UI is built
    """

    NOTE = ""
    COLUMNS = ()
    STRETCH = None
    SEARCH_KEYS = ()
    SORTABLE = False
    EXPORT_HEADER = ()
    READY_TEXT = "Ready."
    EMPTY_EXPORT_TEXT = "Nothing to export yet. Scan first."
    HAS_CONTROL_BAR = True
    HAS_FILTER = True
    FILTER_WIDTH = 25
    PADDING = 8
    TABLE_TITLE = None        # wrap the table in a titled LabelFrame
    TABLE_HEIGHT = None       # fixed pixel height (otherwise fills the tab)
    TABLE_EXPAND = True
    NOTE_WRAP = 1000
    SELECT_MODE = "extended"

    def __init__(self, parent):
        super().__init__(parent, padding=self.PADDING)
        self.rows = []
        self.sort_col = None
        self.sort_reverse = False
        self.status = tk.StringVar(value=self.READY_TEXT)
        self.init_state()
        self._build_ui()
        self.after_build()

    # ---- hooks for subclasses ---------------------------------------------
    def init_state(self):
        pass

    def after_build(self):
        pass

    def build_top(self):
        pass

    def build_controls(self, ctl):
        pass

    def row_values(self, row):
        raise NotImplementedError

    def export_row(self, row):
        raise NotImplementedError

    def export_rows(self):
        return self.rows

    def search_text(self, row):
        return " ".join(str(row[k]) for k in self.SEARCH_KEYS).lower()

    def is_visible(self, row, f):
        return not f or f in self.search_text(row)

    def sort_key(self, row, col):
        return str(row.get(col, "")).lower()

    def sort_starts_descending(self, col):
        return False

    # ---- UI construction --------------------------------------------------
    def _build_ui(self):
        if self.NOTE:
            ttk.Label(self, text=self.NOTE, wraplength=self.NOTE_WRAP,
                      foreground="gray").pack(fill="x")
        self.build_top()
        if self.HAS_CONTROL_BAR:
            ctl = ttk.Frame(self)
            ctl.pack(fill="x", pady=(8, 0))
            self.build_controls(ctl)
        self._build_table()
        self.build_after_table()
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", pady=(8, 0))

    def build_after_table(self):
        pass

    def add_filter_box(self, ctl):
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ctl, textvariable=self.filter_var, width=self.FILTER_WIDTH).pack(side="left")

    def _build_table(self):
        if self.TABLE_TITLE:
            mid = ttk.LabelFrame(self, text=self.TABLE_TITLE, padding=4)
        else:
            mid = ttk.Frame(self)
        mid.pack(fill="both", expand=self.TABLE_EXPAND, pady=(8, 0))
        if self.TABLE_HEIGHT:
            mid.configure(height=self.TABLE_HEIGHT)
            mid.pack_propagate(False)

        keys = [c[0] for c in self.COLUMNS]
        self.tree = ttk.Treeview(mid, columns=keys, show="headings", selectmode=self.SELECT_MODE)
        for key, heading, width in self.COLUMNS:
            cmd = (lambda k=key: self.sort_by(k)) if self.SORTABLE else ""
            self.tree.heading(key, text=heading, command=cmd)
            self.tree.column(key, width=width, anchor="w", stretch=(key == self.STRETCH))
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

    # ---- showing rows -----------------------------------------------------
    def set_status(self, text):
        self.status.set(text)

    def current_filter(self):
        var = getattr(self, "filter_var", None)
        return var.get().strip().lower() if var else ""

    def visible_rows(self):
        f = self.current_filter()
        return [r for r in self.rows if self.is_visible(r, f)]

    def row_tags(self, row):
        """Treeview tags for a row: 'high' / 'context' colour it (see _apply_theme)."""
        return ()

    def insert_row(self, row):
        self.tree.insert("", "end", values=self.row_values(row), tags=self.row_tags(row))

    def apply_filter(self):
        self.tree.delete(*self.tree.get_children())
        for row in self.visible_rows():
            self.insert_row(row)

    def set_rows(self, rows):
        self.rows = rows
        self.apply_filter()

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col, self.sort_reverse = col, self.sort_starts_descending(col)
        self.rows.sort(key=lambda r: self.sort_key(r, col), reverse=self.sort_reverse)
        self.apply_filter()

    # ---- export -----------------------------------------------------------
    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", self.EMPTY_EXPORT_TEXT)
            return
        path = ask_csv_path()
        if not path:
            return
        rows = self.export_rows()
        write_csv(path, self.EXPORT_HEADER, [self.export_row(r) for r in rows])
        self.set_status(f"Exported {len(rows)} rows to {path}")


# ---------------------------------------------------------------------------
# Base class 2: ScanTab - adds the Scan button, background worker, filter box
# ---------------------------------------------------------------------------
class ScanTab(TableTab):
    """A TableTab driven by a 'Scan' button.

    Subclasses implement:
        prepare_scan()   runs on the UI thread; validate inputs / show warnings.
                         Return a tuple of arguments for scan(), or None to abort.
        scan(*args)      does the work (on a background thread when THREADED)
                         and returns the list of rows. May use self.stop_event
                         and self.report_progress(pct).
        done_message(rows)   status text once finished.
    Optional: on_scan_done(rows) to update extra widgets.
    """

    SCAN_LABEL = "Scan"
    BUSY_TEXT = "Scanning..."
    ERROR_TITLE = "Scan failed"
    THREADED = True
    HAS_PROGRESS = False

    def init_state(self):
        self.worker = None
        self.stop_event = threading.Event()

    # ---- hooks ------------------------------------------------------------
    def prepare_scan(self):
        return ()

    def scan(self, *args):
        raise NotImplementedError

    def done_message(self, rows):
        return f"Found {len(rows)} result(s)."

    def on_scan_done(self, rows):
        pass

    # ---- control bar ------------------------------------------------------
    def build_controls(self, ctl):
        self.scan_btn = ttk.Button(ctl, text=self.SCAN_LABEL, command=self.start_scan)
        self.scan_btn.pack(side="left")
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left", padx=6)
        self.build_extra_controls(ctl)
        if self.HAS_FILTER:
            self.add_filter_box(ctl)
        if self.HAS_PROGRESS:
            self.progress = ttk.Progressbar(ctl, length=200, maximum=100)
            self.progress.pack(side="right")

    def build_extra_controls(self, ctl):
        pass

    def report_progress(self, pct):
        """Safe to call from the worker thread."""
        self.after(0, lambda: self.progress.configure(value=pct))

    # ---- running a scan ---------------------------------------------------
    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        args = self.prepare_scan()
        if args is None:
            return
        self.stop_event.clear()
        if self.HAS_PROGRESS:
            self.progress["value"] = 0
        self.scan_btn.config(state="disabled")
        self.set_status(self.BUSY_TEXT)
        if self.THREADED:
            self.worker = threading.Thread(target=self._run, args=args, daemon=True)
            self.worker.start()
        else:
            self._run(*args)

    def _run(self, *args):
        try:
            rows = self.scan(*args)
        except Exception as exc:
            rows = []
            msg = str(exc)
            self.after(0, lambda: messagebox.showerror(self.ERROR_TITLE, msg))
        if self.THREADED:
            self.after(0, lambda: self._finish(rows))
        else:
            self._finish(rows)

    def _finish(self, rows):
        self.on_scan_done(rows)
        self.set_rows(rows)
        self.scan_btn.config(state="normal")
        self.set_status(self.done_message(rows))


# ===========================================================================
# Tabs
# ===========================================================================

# ---------------------------------------------------------------------------
# Memory Scan tab  (streams hits from a worker via a queue, so it overrides
# more of the ScanTab/TableTab behaviour than the others do)
# ---------------------------------------------------------------------------
class MemoryScanTab(TableTab):
    NOTE = ("Red = a distinctive cheat/client name. Amber = a common word that also appears in "
            "innocent software - read the string before reading into it. Start a keyword line "
            "with ? to make it amber.")
    COLUMNS = (("time", "Time", 70), ("pid", "Pid", 60), ("address", "Address", 140),
               ("enc", "Enc", 55), ("keyword", "Keyword", 120), ("string", "String", 600))
    STRETCH = "string"
    EXPORT_HEADER = [c[0] for c in COLUMNS]
    EMPTY_EXPORT_TEXT = "Nothing to export yet."
    SELECT_MODE = "browse"

    def init_state(self):
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.kw_tiers = {}          # keyword -> 'high' | 'context', set when a scan starts

    def after_build(self):
        self.procs.refresh()
        self.after(100, self._poll_queue)

    # ---- UI ----------------------------------------------------------------
    def build_top(self):
        top = ttk.Frame(self)
        top.pack(fill="x")

        self.procs = ProcessPicker(top, status_cb=self.set_status, scan_all_option=True)
        self.procs.pack(side="left", fill="y", padx=(0, 8))

        of = ttk.LabelFrame(top, text="Options", padding=8)
        of.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(of, text="Min string length:").grid(row=0, column=0, sticky="w")
        self.min_len = tk.IntVar(value=5)
        ttk.Spinbox(of, from_=3, to=50, textvariable=self.min_len, width=5
                    ).grid(row=0, column=1, padx=4)
        self.dump_all = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Also save ALL strings to file", variable=self.dump_all
                        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        admin_status_label(of).grid(row=2, column=0, sticky="w", pady=(6, 0))
        if not is_admin():
            ttk.Button(of, text="Run as admin", command=lambda: offer_admin_restart(self)
                       ).grid(row=2, column=1, pady=(6, 0))

        kf = ttk.LabelFrame(top, text="Keywords (one per line; ? prefix = needs context)", padding=8)
        kf.pack(side="left", fill="both", expand=True)
        self.kw_text = tk.Text(kf, height=6, width=30)
        self.kw_text.pack(side="left", fill="both", expand=True)
        self.reset_keywords()
        kb = ttk.Frame(kf)
        kb.pack(side="left", fill="y", padx=(6, 0))
        ttk.Button(kb, text="Load...", command=self.load_keywords).pack(fill="x")
        ttk.Button(kb, text="Save...", command=self.save_keywords).pack(fill="x", pady=4)
        ttk.Button(kb, text="Reset", command=self.reset_keywords).pack(fill="x")

    def build_controls(self, ctl):
        self.start_btn = ttk.Button(ctl, text="Start scan", command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctl, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(ctl, text="Export...", command=self.export).pack(side="left")
        ttk.Button(ctl, text="Clear", command=self.clear_results).pack(side="left", padx=6)
        self.add_filter_box(ctl)
        self.progress = ttk.Progressbar(ctl, length=220, maximum=100)
        self.progress.pack(side="right")

    def build_after_table(self):
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = tk.Text(self, height=4, wrap="word", state="disabled")
        self.detail.pack(fill="x", pady=(8, 0))

    # ---- rows are plain tuples here ---------------------------------------
    def _tier(self, kw):
        return self.kw_tiers.get(kw, "high")

    def row_values(self, row):
        time_, pid, addr, enc, kw, text = row
        label = f"{kw} (context)" if self._tier(kw) == "context" else kw
        return (time_, pid, addr, enc, label, text[:300])

    def row_tags(self, row):
        return (self._tier(row[4]),)

    def search_text(self, row):
        return " ".join(str(v) for v in row).lower()

    def export_row(self, row):
        return list(row)

    # ---- keywords ----------------------------------------------------------
    def get_keywords(self):
        """{keyword: 'high'|'context'} from the keyword box."""
        return parse_keyword_lines(self.kw_text.get("1.0", "end").splitlines())

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
                f.write("\n".join(keyword_lines(self.get_keywords())))

    def reset_keywords(self):
        self.kw_text.delete("1.0", "end")
        self.kw_text.insert("1.0", "\n".join(DEFAULT_KEYWORDS))

    # ---- scanning ----------------------------------------------------------
    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        if self.procs.scan_all.get():
            pids = self.procs.all_pids()
        else:
            pid = self.procs.selected_pid()
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
        self.kw_tiers = keywords
        kw_regex = (re.compile("|".join(re.escape(k) for k in sorted(keywords, key=len, reverse=True)),
                               re.IGNORECASE)
                    if keywords else None)

        self.stop_event.clear()
        self.progress["value"] = 0
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.set_status(f"Scanning {len(pids)} process(es)...")

        self.worker = threading.Thread(
            target=self._worker, args=(pids, kw_regex, min_len, self.dump_all.get()),
            daemon=True)
        self.worker.start()

    def stop_scan(self):
        self.stop_event.set()
        self.set_status("Stopping...")

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
                    if self.is_visible(msg[1], self.current_filter()):
                        self.insert_row(msg[1])
                elif kind == "progress":
                    self.progress["value"] = msg[1]
                elif kind == "status":
                    self.set_status(msg[1])
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
        self.set_status(f"{state}. {summary or 'No data.'}  Log saved: {log_path}")

    # ---- details, clear, export -------------------------------------------
    def show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        visible = self.visible_rows()
        if idx < len(visible):
            row = visible[idx]
            self.detail.config(state="normal")
            self.detail.delete("1.0", "end")
            self.detail.insert("1.0", f"{row[2]} [{row[3]}] kw='{row[4]}' ({self._tier(row[4])})\n{row[5]}")
            self.detail.config(state="disabled")

    def clear_results(self):
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0

    def _write_log(self, path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            if path.lower().endswith(".csv"):
                w = csv.writer(f)
                w.writerow(self.EXPORT_HEADER + ["level"])
                w.writerows(list(r) + [self._tier(r[4])] for r in self.rows)
            else:
                f.write(f"# SS string log - {datetime.now().isoformat()}\n")
                f.write("# Matches are leads to review, not proof of cheating.\n")
                f.write("# 'context' = common word that also appears in innocent software.\n\n")
                for t, pid, addr, enc, kw, text in self.rows:
                    f.write(f"[{t}] PID {pid} {addr} [{enc}] kw='{kw}' ({self._tier(kw)}) :: {text}\n")

    def export(self):
        if not self.rows:
            messagebox.showinfo("Export", self.EMPTY_EXPORT_TEXT)
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text log", "*.txt"), ("CSV", "*.csv")])
        if path:
            self._write_log(path)
            self.set_status(f"Exported {len(self.rows)} rows to {path}")


# ---------------------------------------------------------------------------
# DLL Scanner tab
# ---------------------------------------------------------------------------
class DLLScannerTab(ScanTab):
    NOTE = ("Lists DLLs (and the main exe) currently loaded into a process - "
            "catches cheats injected as a module rather than run as their own "
            "visible program. \"Location\" just tells you whether the file sits "
            "under Windows' system folder or the game's own folder; anything "
            "else is worth a closer look, not automatic proof of anything.")
    COLUMNS = (("name", "Module", 220), ("location", "Location", 110),
               ("base", "Base address", 140), ("size", "Size (bytes)", 90),
               ("path", "Full path", 440))
    STRETCH = "path"
    SEARCH_KEYS = ("name", "path", "location")
    EXPORT_HEADER = ["module", "location", "base_address", "size_bytes", "path"]
    SCAN_LABEL = "Scan loaded modules"
    THREADED = False        # a module snapshot is near-instant

    def build_top(self):
        self.procs = ProcessPicker(self, status_cb=self.set_status, show_admin=True)
        self.procs.pack(fill="x", pady=(8, 0))

    def after_build(self):
        self.procs.refresh()

    def prepare_scan(self):
        pid = self.procs.selected_pid()
        if not pid:
            messagebox.showwarning("No process", "No target process selected. Try Refresh.")
            return None
        modules = list_modules(pid)
        if modules is None:
            messagebox.showerror(
                "Couldn't read modules",
                f"Could not snapshot modules for PID {pid} (error {ctypes.get_last_error()}). "
                f"Try 'Run as admin', or the process may have exited.")
            return None
        self.scanned_pid = pid
        return (modules, get_process_exe_dir(pid))

    def scan(self, modules, game_dir):
        rows = []
        for m in modules:
            if is_system_module_path(m["path"]):
                location = "system"
            elif game_dir and m["path"].lower().startswith(game_dir.lower()):
                location = "game folder"
            else:
                location = "other"
            rows.append({**m, "location": location})
        return rows

    def done_message(self, rows):
        return f"PID {self.scanned_pid}: {len(rows)} loaded module(s)."

    def row_values(self, m):
        return (m["name"], m["location"], f"0x{m['base']:016X}", m["size"], m["path"])

    def export_row(self, m):
        return [m["name"], m["location"], f"0x{m['base']:016X}", m["size"], m["path"]]


# ---------------------------------------------------------------------------
# Recycle Bin tab
# ---------------------------------------------------------------------------
class RecycleBinTab(ScanTab):
    NOTE = ("Reads deleted-file metadata from each drive's $Recycle.Bin. "
            "Only the current Windows account's own recycle bin folder is "
            "reliably readable without admin rights.")
    COLUMNS = (("deleted", "Deleted", 150), ("original_path", "Original path", 620),
               ("size", "Size (bytes)", 90), ("drive", "Drive", 60), ("sid", "Account SID", 160))
    STRETCH = "original_path"
    SEARCH_KEYS = ("original_path",)
    EXPORT_HEADER = ["deleted_time", "original_path", "size_bytes", "drive", "sid"]
    FILTER_WIDTH = 30
    SCAN_LABEL = "Scan Recycle Bin"
    BUSY_TEXT = "Scanning $Recycle.Bin on all drives..."
    ERROR_TITLE = "Recycle Bin scan failed"

    def scan(self):
        return enumerate_recycle_bin(self.stop_event)

    def done_message(self, rows):
        return f"Found {len(rows)} deleted-file record(s)."

    def row_values(self, r):
        return (fmt_dt(r["deleted_time"]), r["original_path"], r["file_size"], r["drive"], r["sid"])

    def export_row(self, r):
        return [fmt_dt(r["deleted_time"]), r["original_path"], r["file_size"], r["drive"], r["sid"]]


# ---------------------------------------------------------------------------
# Prefetch tab
# ---------------------------------------------------------------------------
class PrefetchTab(ScanTab):
    NOTE = ("Reads C:\\Windows\\Prefetch for program run history. Needs admin rights "
            "to read, and only exists if prefetch is enabled. Windows 10/11 files are "
            "decompressed and read in full: \"Last run\", \"Run count\" and \"Earlier "
            "runs\" come from inside the file (the last 8 runs). If a file can't be "
            "parsed, the file-system times are shown instead and \"Parsed\" says no.")
    COLUMNS = (("program", "Program", 240), ("hash", "Hash", 80), ("created", "First seen", 140),
               ("last_run", "Last run", 140), ("run_count", "Run count", 70),
               ("earlier", "Earlier runs (newest first)", 330), ("parsed", "Parsed", 90))
    STRETCH = "earlier"
    SEARCH_KEYS = ("program",)
    EXPORT_HEADER = ["program", "hash", "first_seen", "last_run", "run_count",
                     "earlier_runs", "parsed", "format_version", "parse_error"]
    FILTER_WIDTH = 30
    SCAN_LABEL = "Scan Prefetch"
    BUSY_TEXT = "Scanning Prefetch..."
    ERROR_TITLE = "Prefetch scan failed"

    def prepare_scan(self):
        if not is_admin():
            messagebox.showwarning("Admin needed",
                                   "Reading the Prefetch folder usually needs admin rights. "
                                   "Restart as admin from the Memory Scan tab if this comes back empty.")
        return ()

    def scan(self):
        return enumerate_prefetch()

    def done_message(self, rows):
        parsed = sum(1 for r in rows if r["parsed"])
        return f"Found {plural(len(rows), 'prefetch entry', 'prefetch entries')} ({parsed} parsed)."

    @staticmethod
    def _last_run(r):
        return r["last_run"] or r["last_run_fs"]

    @staticmethod
    def _earlier(r):
        return ", ".join(fmt_dt(t) for t in r["run_times"][1:])

    def row_values(self, r):
        return (r["program"], r["hash"], fmt_dt(r["created"]), fmt_dt(self._last_run(r)),
                r["run_count"] if r["run_count"] is not None else "-",
                self._earlier(r), "yes" if r["parsed"] else "no")

    def export_row(self, r):
        version = PF_VERSIONS.get(r["version"], r["version"] or "")
        return [r["program"], r["hash"], fmt_dt(r["created"]), fmt_dt(self._last_run(r)),
                r["run_count"] if r["run_count"] is not None else "", self._earlier(r),
                r["parsed"], version, r["error"]]


# ---------------------------------------------------------------------------
# Mods Scanner tab
# ---------------------------------------------------------------------------
class ModsScannerTab(ScanTab):
    NOTE = ("Finds every \"mods\" folder under each launcher's data folder (including per-profile "
            "ones like CurseForge, Modrinth App and Dawn, and one level of subfolders such as "
            "mods\\1.12.2) and, optionally, the installed game versions. Each jar is opened and "
            "its class/package/resource names, file name and declared mod name are checked "
            "against the Memory Scan keyword list, so a renamed cheat is still caught. Red = "
            "distinctive cheat name, amber = common word (check the evidence in the box below). "
            "Hashes are skipped for mods over 20 MB (64 MB for game versions).")
    COLUMNS = (("flags", "Flags", 150), ("file", "File / version", 190),
               ("info", "Declared name / info", 150), ("kind", "Kind", 55),
               ("launcher", "Launcher", 100), ("profile", "Profile/instance", 110),
               ("size", "Size (bytes)", 80), ("modified", "Modified", 125),
               ("sha256", "SHA-256", 200))
    STRETCH = "sha256"
    SEARCH_KEYS = ("flags", "file", "info", "kind", "profile", "launcher")
    EXPORT_HEADER = ["flags", "kind", "launcher", "profile", "file", "declared_name_or_info",
                     "size_bytes", "modified", "sha256", "evidence", "full_path"]
    SCAN_LABEL = "Scan mods"
    BUSY_TEXT = "Scanning for mods folders and opening jars..."
    ERROR_TITLE = "Mods scan failed"
    HAS_PROGRESS = True
    SORTABLE = True

    def init_state(self):
        super().init_state()
        self.keyword_count = 0

    def build_top(self):
        self.picker = add_path_picker(
            self, "Search locations", defaults=get_default_client_roots(),
            default_caption="Default launcher folders (unchecked ones weren't found):",
            custom_caption="Custom launcher/instance folder:")
        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.include_versions = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Also list installed game versions (the versions folder)",
                        variable=self.include_versions).pack(anchor="w")
        row = ttk.Frame(opt)
        row.pack(fill="x", pady=(4, 0))
        ttk.Label(row, text="Extra keywords for this scan (comma-separated, ? prefix = needs context):"
                  ).pack(side="left")
        self.extra_kw = tk.StringVar()
        ttk.Entry(row, textvariable=self.extra_kw, width=40).pack(side="left", padx=6)

    def build_after_table(self):
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.detail = tk.Text(self, height=4, wrap="word", state="disabled")
        self.detail.pack(fill="x", pady=(8, 0))

    def _keyword_tiers(self):
        """Use the Memory Scan tab's (possibly edited) keyword box so there is one list
        to maintain; fall back to the defaults. Extra keywords are added on top."""
        tiers = parse_keyword_lines(DEFAULT_KEYWORDS)
        mem = getattr(self.winfo_toplevel(), "tabs", {}).get("Memory Scan")
        if mem is not None:
            tiers = mem.get_keywords() or tiers
        for kw, tier in parse_keyword_lines(self.extra_kw.get().split(",")).items():
            if tiers.get(kw) != "high":
                tiers[kw] = tier
        return tiers

    def prepare_scan(self):
        roots = self.picker.selected()
        if not roots:
            messagebox.showwarning("No locations", "Select at least one default folder or add a custom one.")
            return None
        return (roots, self._keyword_tiers(), self.include_versions.get())

    def scan(self, roots, tiers, include_versions):
        self.keyword_count = len(tiers)
        return scan_mods(roots, tiers, include_versions, self.stop_event, self.report_progress)

    def done_message(self, rows):
        high = sum(1 for r in rows if r["severity"] == "high")
        ctx = sum(1 for r in rows if r["severity"] == "context")
        mods = sum(1 for r in rows if r["kind"] == "mod")
        return (f"Found {mods} mod jar(s) and {len(rows) - mods} game version(s); "
                f"{high} flagged red, {ctx} amber ({self.keyword_count} keywords checked).")

    def row_values(self, m):
        return (m["flags"], m["file"], m["info"], m["kind"], m["launcher"], m["profile"],
                m["size"], fmt_dt(m["modified"]), m["sha256"])

    def row_tags(self, m):
        return (m["severity"],) if m["severity"] else ()

    def export_row(self, m):
        return [m["flags"], m["kind"], m["launcher"], m["profile"], m["file"], m["info"],
                m["size"], fmt_dt(m["modified"]), m["sha256"], m["evidence"], m["path"]]

    def sort_key(self, r, col):
        if col == "flags":
            return (SEVERITY_RANK[r["severity"]], r["flags"].lower())
        if col == "size":
            return r["size"]
        if col == "modified":
            return r["modified"]
        return str(r.get(col, "")).lower()

    def sort_starts_descending(self, col):
        return col in ("flags", "size", "modified")

    def show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        visible = self.visible_rows()
        idx = self.tree.index(sel[0])
        if idx >= len(visible):
            return
        m = visible[idx]
        text = (f"{m['path']}\n"
                f"Flags: {m['flags'] or 'none'}\n"
                f"Evidence: {m['evidence'] or '-'}\n"
                f"SHA-256: {m['sha256'] or '-'}")
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.config(state="disabled")


# ---------------------------------------------------------------------------
# Servers tab (recent/saved servers across launchers and profiles)
# ---------------------------------------------------------------------------
class ServersTab(ScanTab):
    NOTE = ("Reads servers.dat (the multiplayer server list) from every "
            "launcher/instance folder found, including profile-based "
            "launchers where each instance keeps its own list.")
    COLUMNS = (("launcher", "Launcher", 130), ("profile", "Profile/instance", 150),
               ("name", "Server name", 200), ("ip", "Address", 200), ("source", "Source file", 320))
    STRETCH = "source"
    SEARCH_KEYS = ("name", "ip", "profile", "launcher")
    EXPORT_HEADER = ["launcher", "profile", "server_name", "address", "source_file"]
    SCAN_LABEL = "Scan servers"
    BUSY_TEXT = "Scanning for servers.dat files..."
    ERROR_TITLE = "Server scan failed"

    def build_top(self):
        self.picker = add_path_picker(
            self, "Search locations", defaults=get_default_client_roots(),
            default_caption="Default launcher folders (unchecked ones weren't found):",
            custom_caption="Custom launcher/instance folder:")

    def prepare_scan(self):
        roots = self.picker.selected()
        if not roots:
            messagebox.showwarning("No locations", "Select at least one default folder or add a custom one.")
            return None
        return (roots,)

    def scan(self, roots):
        return scan_servers(roots)

    def done_message(self, rows):
        return f"Found {plural(len(rows), 'saved server entry', 'saved server entries')}."

    def row_values(self, r):
        return (r["launcher"], r["profile"], r["name"], r["ip"], r["source"])

    def export_row(self, r):
        return [r["launcher"], r["profile"], r["name"], r["ip"], r["source"]]


# ---------------------------------------------------------------------------
# Installed Programs tab
# ---------------------------------------------------------------------------
class InstalledProgramsTab(ScanTab):
    NOTE = ("Reads the registry's list of installed programs (all users, 32-bit, "
            "and current user). Programs that were uninstalled sometimes leave "
            "their registry entry behind, so this can show software that's no "
            "longer on the PC. \"Key modified\" is when the entry was last "
            "written - click any column header to sort.")
    COLUMNS = (("name", "Name", 260), ("version", "Version", 100), ("publisher", "Publisher", 170),
               ("install_date", "Install date", 100), ("key_modified", "Key modified", 140),
               ("scope", "Scope", 120), ("location", "Install location", 300))
    STRETCH = "location"
    SEARCH_KEYS = ("name", "publisher", "location")
    EXPORT_HEADER = ["name", "version", "publisher", "install_date", "key_modified",
                     "scope", "install_location"]
    FILTER_WIDTH = 30
    SORTABLE = True
    SCAN_LABEL = "Scan installed programs"
    BUSY_TEXT = "Reading installed programs from the registry..."

    def scan(self):
        return enumerate_installed_programs()

    def done_message(self, rows):
        return f"Found {plural(len(rows), 'installed program entry', 'installed program entries')}."

    def sort_key(self, r, col):
        if col == "key_modified":
            return r["key_modified"] or datetime.min
        return str(r[col]).lower()

    def sort_starts_descending(self, col):
        return col == "key_modified"

    def row_values(self, r):
        return (r["name"], r["version"], r["publisher"], r["install_date"],
                fmt_dt(r["key_modified"]), r["scope"], r["location"])

    def export_row(self, r):
        return list(self.row_values(r))


# ---------------------------------------------------------------------------
# Hosts Check tab
# ---------------------------------------------------------------------------
class HostsCheckTab(ScanTab):
    NOTE = ("Reads the Windows hosts file. A stock hosts file has only comments, "
            "so any active entry beyond localhost is worth a look. Entries that "
            "point a domain at 0.0.0.0 / 127.0.0.1 block it; entries pointing "
            "at another IP redirect it. Some cheat clients add entries to stop "
            "anti-cheat or report domains from loading - but plenty of "
            "legitimate software (ad blockers, dev tools) edits this file too, "
            "so check what a flagged entry actually is before reading into it.")
    COLUMNS = (("line", "Line", 60), ("ip", "IP", 140), ("host", "Hostname", 320),
               ("kind", "Type", 200), ("note", "Note", 300))
    STRETCH = "note"
    EXPORT_HEADER = ["line", "ip", "hostname", "type", "note"]
    EMPTY_EXPORT_TEXT = "Nothing to export yet. Run a check first."
    SCAN_LABEL = "Check hosts file"
    BUSY_TEXT = "Reading the hosts file..."
    THREADED = False
    HAS_FILTER = False

    def build_extra_controls(self, ctl):
        ttk.Label(ctl, text=f"File: {HOSTS_PATH}", foreground="gray").pack(side="left", padx=(16, 0))

    def scan(self):
        self.result = parse_hosts_file()
        return [] if self.result["error"] else self.result["rows"]

    def done_message(self, rows):
        if self.result["error"]:
            return f"Couldn't read the hosts file: {self.result['error']}"
        extra = [r for r in rows if r["kind"] != "default (localhost)"]
        stamp = f"Last modified {fmt_dt(self.result['modified'])}, {self.result['size']} bytes."
        if extra:
            return f"{plural(len(extra), 'active entry', 'active entries')} beyond localhost. {stamp}"
        return f"No active entries beyond localhost - looks clean. {stamp}"

    def row_values(self, r):
        return (r["line"], r["ip"], r["host"], r["kind"], r["note"])

    def export_row(self, r):
        return list(self.row_values(r))


# ---------------------------------------------------------------------------
# Process Timeline tab (refreshes live instead of running a one-off scan, so it
# sits on TableTab rather than ScanTab)
# ---------------------------------------------------------------------------
class ProcessTimelineTab(TableTab):
    NOTE = ("Lists processes that started after a reference time (e.g. when "
            "Minecraft launched). This only sees processes still running now "
            "and whatever starts from here on - Windows doesn't keep deep launch "
            "history by default.")
    COLUMNS = (("start", "Started", 150), ("delta", "After ref. (s)", 90), ("pid", "PID", 70),
               ("name", "Name", 220), ("path", "Path", 450))
    STRETCH = "path"
    EXPORT_HEADER = ["started", "seconds_after_reference", "pid", "name", "path"]
    EMPTY_EXPORT_TEXT = "Nothing to export yet. Refresh first."
    READY_TEXT = "Set a reference time to begin."
    HAS_CONTROL_BAR = False       # this tab lays out its own controls in build_top

    def init_state(self):
        self.ref_epoch = None
        self.auto_job = None
        self.java_proc_map = {}

    def after_build(self):
        self.refresh_java_list()

    def build_top(self):
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
        ttk.Spinbox(ctl2, from_=2, to=60, textvariable=self.interval, width=4).pack(side="left")
        ttk.Label(ctl2, text="sec").pack(side="left", padx=(2, 12))
        ttk.Button(ctl2, text="Refresh now", command=self.refresh).pack(side="left")
        ttk.Button(ctl2, text="Export...", command=self.export).pack(side="left", padx=6)

    def row_values(self, r):
        return (fmt_dt(r["start"]), f"{r['delta']:.1f}", r["pid"], r["name"], r["exe"])

    def export_row(self, r):
        return list(self.row_values(r))

    def refresh_java_list(self):
        if not psutil:
            self.set_status("psutil unavailable - can't list processes.")
            return
        self.java_proc_map = {}
        labels = []
        for pid, name, ct in list_java_candidates():
            label = f"{name}  (PID {pid})  started {datetime.fromtimestamp(ct).strftime('%H:%M:%S')}"
            self.java_proc_map[label] = (pid, ct)
            labels.append(label)
        self.java_combo["values"] = labels
        if labels:
            self.java_combo.current(0)
        else:
            self.java_var.set("")
        self.set_status(f"Found {len(labels)} java/client process(es) to choose from.")

    def _set_reference(self, epoch, how):
        self.ref_epoch = epoch
        self.ref_label.config(text=f"Reference time: {fmt_dt(datetime.fromtimestamp(epoch))} ({how})")
        self.refresh()

    def use_selected_java(self):
        info = self.java_proc_map.get(self.java_var.get())
        if not info:
            messagebox.showwarning("No selection", "Pick a process from the list first "
                                   "(click Refresh list if it's empty).")
            return
        pid, ct = info
        self._set_reference(ct, f"PID {pid}, picked manually")

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
        self._set_reference(t, "Minecraft launch")

    def use_now(self):
        self._set_reference(datetime.now().timestamp(), "manual")

    def refresh(self):
        if self.ref_epoch is None:
            self.set_status("Set a reference time first.")
            return
        self.set_rows(list_processes_since(self.ref_epoch))
        self.set_status(f"{len(self.rows)} process(es) started after the reference time. "
                        f"Last refreshed {datetime.now().strftime('%H:%M:%S')}.")

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


# ---------------------------------------------------------------------------
# Log Checker tab = two ScanTab panels (usernames in logs, launcher accounts)
# stacked inside one scrollable page.
# ---------------------------------------------------------------------------
class LogsPanel(ScanTab):
    NOTE = ("Scans Minecraft-style log files for usernames seen joining, "
            "leaving, or chatting, and lists each unique one under Possible "
            "Alts below. This only reads log files already on disk. The lower table "
            "lists every account the logs say LAUNCHED the game on this PC "
            "(\"Setting user: ...\" lines) - several names there is the strongest alt "
            "signal here. The upper table is only players seen online, which is a much "
            "weaker signal, so by default the launching accounts are hidden from it.")
    COLUMNS = (("username", "Username", 150), ("likely_you", "Likely you?", 80),
               ("count", "Occurrences", 80), ("files", "Seen in file(s)", 200),
               ("first_time", "First seen", 130), ("sample", "Sample log line", 330))
    STRETCH = "sample"
    EXPORT_HEADER = ["username", "likely_you", "occurrences", "files", "first_seen", "sample_line"]
    PADDING = 0
    TABLE_TITLE = "Players seen in logs (weak signal - launching accounts are listed below)"
    TABLE_HEIGHT = 260
    SCAN_LABEL = "Scan logs"
    BUSY_TEXT = "Scanning log files..."
    ERROR_TITLE = "Log scan failed"
    HAS_PROGRESS = True

    def init_state(self):
        super().init_state()
        self.local_accounts = {}            # accounts that launched the game (shown below)
        self.local_names = set()            # names shown as "likely you"
        self.pending_local_accounts = {}    # set by the worker, applied in on_scan_done

    def build_top(self):
        self.picker = add_path_picker(
            self, "Log locations", defaults=get_default_log_paths(), list_height=4,
            default_caption="Default paths (unchecked ones weren't found on this PC):",
            custom_caption="Custom path (for clients that don't keep logs in .minecraft):",
            empty_text="(%APPDATA% not available)")

        ef = ttk.Frame(self)
        ef.pack(fill="x", pady=(8, 0))
        ttk.Label(ef, text="Also exclude (comma-separated - friends, teammates, etc.):"
                  ).pack(anchor="w")
        self.exclude_var = tk.StringVar()
        self.exclude_var.trace_add("write", lambda *_: self.apply_filter())
        ttk.Entry(ef, textvariable=self.exclude_var, width=60).pack(fill="x")
        self.auto_exclude_local = tk.BooleanVar(value=True)
        ttk.Checkbutton(ef, text="Hide the launching account(s) from the players table above",
                        variable=self.auto_exclude_local,
                        command=self.apply_filter).pack(anchor="w", pady=(4, 0))
        self.local_names_label = ttk.Label(ef, text="Launching accounts: none yet (scan first)",
                                           foreground="gray")
        self.local_names_label.pack(anchor="w")

    ACCOUNT_COLUMNS = (("account", "Account", 170), ("sessions", "Launches", 70),
                       ("first_seen", "First seen", 140), ("last_seen", "Last seen", 140),
                       ("files", "Seen in file(s)", 300))

    def build_after_table(self):
        box = ttk.LabelFrame(
            self, padding=4,
            text="Accounts that launched the game on this PC (several = likely alts)")
        box.pack(fill="x", pady=(8, 0))
        inner = ttk.Frame(box)
        inner.pack(fill="x")
        keys = [c[0] for c in self.ACCOUNT_COLUMNS]
        self.acct_tree = ttk.Treeview(inner, columns=keys, show="headings", height=5,
                                      selectmode="browse")
        for key, heading, width in self.ACCOUNT_COLUMNS:
            self.acct_tree.heading(key, text=heading)
            self.acct_tree.column(key, width=width, anchor="w", stretch=(key == "files"))
        sb = ttk.Scrollbar(inner, orient="vertical", command=self.acct_tree.yview)
        self.acct_tree.configure(yscrollcommand=sb.set)
        self.acct_tree.pack(side="left", fill="x", expand=True)
        sb.pack(side="left", fill="y")
        ttk.Button(box, text="Export accounts...", command=self.export_accounts
                   ).pack(anchor="w", pady=(4, 0))

    def _account_rows(self):
        return [(name, a["sessions"], a["first_seen"], a["last_seen"],
                 ", ".join(sorted(a["files"])))
                for name, a in sorted(self.local_accounts.items(),
                                      key=lambda kv: kv[1]["first_seen"])]

    def export_accounts(self):
        rows = self._account_rows()
        if not rows:
            messagebox.showinfo("Export", "No launching accounts found yet. Scan logs first.")
            return
        path = ask_csv_path()
        if path:
            write_csv(path, ["account", "launches", "first_seen", "last_seen", "files"], rows)
            self.set_status(f"Exported {len(rows)} account(s) to {path}")

    # ---- scanning ----------------------------------------------------------
    def prepare_scan(self):
        paths = [path for _label, path in self.picker.selected()]
        if not paths:
            messagebox.showwarning("No paths", "Select at least one default path or add a custom one.")
            return None
        return (paths,)

    def scan(self, paths):
        self.pending_local_accounts = {}
        agg, local_accounts = scan_logs(paths, self.stop_event, self.report_progress)
        self.pending_local_accounts = local_accounts
        rows = [{"name": name, **info} for name, info in agg.items()]
        rows.sort(key=lambda r: -r["count"])
        return rows

    def on_scan_done(self, rows):
        self.local_accounts = self.pending_local_accounts
        self.local_names = set(self.local_accounts)
        self.acct_tree.delete(*self.acct_tree.get_children())
        for values in self._account_rows():
            self.acct_tree.insert("", "end", values=values)
        if self.local_names:
            normal_fg = ttk.Style(self).lookup("TLabel", "foreground") or "black"
            self.local_names_label.config(
                text="Launching account(s): " + ", ".join(sorted(self.local_names)),
                foreground=normal_fg)
        else:
            self.local_names_label.config(
                text="Launching accounts: none found (no \"Setting user:\" line in these logs)",
                foreground="gray")

    def done_message(self, rows):
        n = len(self.local_names)
        msg = f"Found {len(rows)} unique username(s) across the scanned logs. "
        if n > 1:
            return msg + f"{n} different accounts launched the game on this PC - worth a look."
        return msg + f"{plural(n, 'account', 'accounts')} launched the game here."

    # ---- filtering / display ----------------------------------------------
    def _excluded_set(self):
        manual = {n.strip().lower() for n in self.exclude_var.get().split(",") if n.strip()}
        if self.auto_exclude_local.get():
            manual |= {n.lower() for n in self.local_names}
        return manual

    def visible_rows(self):
        f = self.current_filter()
        excluded = self._excluded_set()
        return [r for r in self.rows
                if r["name"].lower() not in excluded and (not f or f in r["name"].lower())]

    def export_rows(self):
        excluded = self._excluded_set()
        return [r for r in self.rows if r["name"].lower() not in excluded]

    def _likely_you(self, r):
        return "yes" if r["name"].lower() in {n.lower() for n in self.local_names} else ""

    def row_values(self, r):
        return (r["name"], self._likely_you(r), r["count"], ", ".join(sorted(r["files"])),
                r["first_time"], r["sample"][:200])

    def export_row(self, r):
        return [r["name"], self._likely_you(r), r["count"], ", ".join(sorted(r["files"])),
                r["first_time"], r["sample"]]


class AccountsPanel(ScanTab):
    NOTE = ("Reads profile/display names out of launcher account files already "
            "on this PC - i.e. which accounts are logged into which launcher. "
            "Only player names are shown; access tokens, passwords, e-mail "
            "addresses and other credential-looking values are never read out, "
            "whatever the file contains.")
    COLUMNS = (("source", "Launcher file", 480), ("name", "Profile / display name", 260))
    STRETCH = "source"
    EXPORT_HEADER = ["source_file", "profile_name"]
    PADDING = 0
    TABLE_HEIGHT = 160
    TABLE_EXPAND = False
    SCAN_LABEL = "Scan accounts"
    BUSY_TEXT = "Scanning launcher account files..."
    ERROR_TITLE = "Account scan failed"
    HAS_FILTER = False

    def build_top(self):
        self.picker = PathPicker(
            self, defaults=get_default_account_files(), files=True,
            default_caption="Default launcher files (unchecked ones weren't found):",
            custom_caption="Custom account/profile file (e.g. another launcher's accounts.json):",
            empty_text="(%APPDATA% not available)")
        self.picker.pack(fill="x", pady=(8, 0))

    def prepare_scan(self):
        paths = [path for _label, path in self.picker.selected()]
        if not paths:
            messagebox.showwarning("No files", "Select at least one default file or add a custom one.")
            return None
        return (paths,)

    def scan(self, paths):
        result = scan_account_files(paths)
        self.file_count = len(result)
        return [{"source": src, "name": name} for src, names in result.items() for name in sorted(names)]

    def done_message(self, rows):
        return f"Found {len(rows)} profile name(s) across {self.file_count} file(s)."

    def row_values(self, r):
        return (r["source"], r["name"])

    def export_row(self, r):
        return [r["source"], r["name"]]


class LogCheckerTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=0)
        self.scroll_canvas = tk.Canvas(self, highlightthickness=0)
        canvas = self.scroll_canvas
        vsb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas, padding=8)
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"), add="+")

        self.logs = LogsPanel(body)
        self.logs.pack(fill="both", expand=True)

        box = ttk.LabelFrame(body, text="Launcher accounts / profile names", padding=8)
        box.pack(fill="x", pady=(16, 0))
        self.accounts = AccountsPanel(box)
        self.accounts.pack(fill="x")


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
                    select_fg="#ffffff", high="#c62828", context="#a15c00")
DARK_COLORS = dict(bg="#1e1e1e", fg="#e6e6e6", field_bg="#2b2b2b", select="#3a6ea5",
                   select_fg="#ffffff", high="#ff6b6b", context="#e0a030")

# (tab title, tab class) in display order - add a new tab by adding a line here.
TABS = [
    ("Memory Scan", MemoryScanTab),
    ("DLL Scanner", DLLScannerTab),
    ("Log Checker", LogCheckerTab),
    ("Mods Scanner", ModsScannerTab),
    ("Servers", ServersTab),
    ("Recycle Bin", RecycleBinTab),
    ("Prefetch", PrefetchTab),
    ("Installed Programs", InstalledProgramsTab),
    ("Hosts Check", HostsCheckTab),
    ("Process Timeline", ProcessTimelineTab),
    ("Credits", CreditsTab),
]


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
        self.tabs = {}
        for title, tab_class in TABS:
            tab = tab_class(nb)
            nb.add(tab, text=title)
            self.tabs[title] = tab

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
        self._recolor_classic_widgets(self, c)

    def _recolor_classic_widgets(self, widget, c):
        """ttk styles don't cover classic tk widgets (Text/Listbox/Canvas), so walk the
        whole widget tree and recolor those by hand. New tabs get this for free."""
        for child in widget.winfo_children():
            try:
                if isinstance(child, tk.Text):
                    child.configure(bg=c["field_bg"], fg=c["fg"], insertbackground=c["fg"],
                                    selectbackground=c["select"], selectforeground=c["select_fg"],
                                    highlightthickness=0)
                elif isinstance(child, tk.Listbox):      # Listbox has no insertbackground option
                    child.configure(bg=c["field_bg"], fg=c["fg"],
                                    selectbackground=c["select"], selectforeground=c["select_fg"],
                                    highlightthickness=0)
                elif isinstance(child, tk.Canvas):
                    child.configure(bg=c["bg"])
                elif isinstance(child, ttk.Treeview):    # severity colours for flagged rows
                    child.tag_configure("high", foreground=c["high"])
                    child.tag_configure("context", foreground=c["context"])
            except tk.TclError:
                pass
            self._recolor_classic_widgets(child, c)


if __name__ == "__main__":
    App().mainloop()
