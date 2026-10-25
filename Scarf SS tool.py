"""
Scarf's SS Tool - Minecraft screenshare helper GUI (Windows)

Tabs:
  - Memory Scan:        scans a running process's memory for keyword strings
  - DLL Scanner:        lists DLLs loaded into a process
  - Log Checker:        usernames seen in logs (possible alts) + launcher accounts
  - Mods Scanner:       finds mods folders, inspects jars and game versions
  - Versions Audit:     version folders vs. official hashes, JVM args, launcher profiles
  - Servers:            saved servers from servers.dat
  - Recycle Bin:        reads $Recycle.Bin metadata for deleted-file history
  - Prefetch:           reads C:\\Windows\\Prefetch (program run history, incl. Win10/11)
  - Crash Reports:      Minecraft crash reports, JVM hs_err logs, Windows Error Reports
  - Installed Programs: registry uninstall entries, including leftovers
  - Hosts Check:        active entries in the hosts file
  - Process Timeline:   lists processes that started after a reference time

Built for VISIBLE use during a screenshare the other person has agreed to.
Everything here reads artifacts already on disk or live process metadata;
nothing here captures keystrokes or runs hidden/in the background.
A match or entry is a lead to review, not proof of cheating.

Just run: python Scarf_SS_tool.py
Missing dependencies (psutil, sv-ttk) are installed automatically on first launch.

Code layout: backend scanners first, then the GUI. Every table tab is built on
the TableTab / ScanTab base classes - see the "GUI" section for how to add one.
"""

import sys

if sys.platform != "win32":
    sys.exit("This tool only works on Windows.")

# Version info. build.py reads and bumps these (python build.py --bump).
APP_NAME = "Scarf's SS Tool"
APP_VERSION = "2.0"
APP_STAGE = "Beta"          # "Beta", or "" for a stable release
VERSION_LABEL = f"{APP_VERSION} {APP_STAGE}".strip()
FROZEN = getattr(sys, "frozen", False)      # True when running as the built .exe

import csv
import ctypes
import ctypes.wintypes as wt
import gzip
import hashlib
import importlib
import json
import os
import queue
import re
import string
import struct
import subprocess
import tempfile
import threading
import winreg
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# Folder next to the script, or next to the .exe when built (a one-file exe's
# __file__ points at a temp folder that is deleted on exit).
APP_DIR = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------
REQUIRED = {"psutil": "psutil", "sv_ttk": "sv-ttk"}  # import name -> pip package name


def ensure_dependencies():
    if FROZEN:      # the exe already bundles everything; pip would re-launch the exe
        return
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
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *missing])
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

try:
    import sv_ttk          # Sun Valley theme: Windows 11 look for plain ttk widgets
except ImportError:
    sv_ttk = None          # falls back to the built-in "clam" theme

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
MC_NAME_HINTS = ("javaw", "java", "minecraft", "lunarclient", "lunar", "badlion")


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


# ---------------------------------------------------------------------------
# WinAPI
# ---------------------------------------------------------------------------
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


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
    """Ask Windows to restart this script elevated. Returns False if the user
    declined the UAC prompt (ShellExecute returns <= 32 on failure)."""
    args = sys.argv[1:] if FROZEN else [os.path.abspath(sys.argv[0]), *sys.argv[1:]]
    params = " ".join(f'"{a}"' for a in args)
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1) > 32


def filetime_to_datetime(ft):
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01, UTC) to a local datetime."""
    if not ft:
        return None
    try:
        return datetime.fromtimestamp((ft - 116444736000000000) / 10_000_000)
    except (OverflowError, OSError, ValueError):
        return None


def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "-"


# ---------------------------------------------------------------------------
# Windows path helpers
# ---------------------------------------------------------------------------
def _win_norm(path):
    """Lower-cased, backslash-normalised path for prefix comparisons."""
    return path.replace("/", "\\").lower()


def _win_basename(path):
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1]


def _win_dirname(path):
    return "\\".join(re.split(r"[\\/]", path.rstrip("\\/"))[:-1])


def is_under(path, folder):
    """True if path is inside folder (so C:\\Windows2 is NOT under C:\\Windows)."""
    return bool(folder) and _win_norm(path).startswith(_win_norm(folder).rstrip("\\") + "\\")


def _mtime(path):
    try:
        return datetime.fromtimestamp(os.stat(path).st_mtime)
    except OSError:
        return None


def _read_file_head(path, limit=256 * 1024):
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _json_loads(raw):
    try:
        return json.loads(raw.decode("utf-8-sig", errors="ignore"), strict=False)
    except ValueError:
        return None


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
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                             creationflags=subprocess.CREATE_NO_WINDOW).stdout
        for row in csv.reader(out.splitlines()):
            if len(row) >= 2 and name_filter in row[0].lower():
                try:
                    results.append((int(row[1]), row[0]))
                except ValueError:
                    pass
    return sorted(results, key=lambda r: (r[1].lower(), r[0]))


def iter_regions(handle):
    """Yield (base, size) for every committed, readable memory region."""
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
        if not size:                      # guard against an endless loop
            break
        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_NOACCESS)
                and not (mbi.Protect & PAGE_GUARD)):
            yield base, size
        address = base + size


def read_chunk(handle, base, size, buf=None):
    """Read up to `size` bytes. Pass a reusable ctypes buffer (>= size) to avoid
    allocating and zero-filling a new one - up to 64 MB - for every chunk."""
    if buf is None or len(buf) < size:
        buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
    if not ok and read.value == 0:
        return b""
    return ctypes.string_at(buf, read.value)


# --- Keyword-only fast path -------------------------------------------------
# Listing every string in a chunk is slow, and a keyword scan only needs the few
# that contain a keyword. So instead: lower-case the chunk once (cheap), search it
# for the plain keyword bytes (much faster than a case-insensitive regex), and
# only then grow each hit into the full string around it. Measured ~4x faster
# with identical results. Used only when "save all strings" is off.
MAX_CONTEXT = 2000        # how far to look left/right of a hit for the string's edges
CHUNK_OVERLAP = 4096      # extra bytes read either side of a chunk so strings that straddle
                          # a chunk boundary are seen whole (must be > MAX_CONTEXT)
IS_32BIT_PYTHON = ctypes.sizeof(ctypes.c_void_p) == 4


def build_fast_matchers(keywords):
    """(ascii_pattern, utf16_pattern) for the fast path, or None when it can't be
    used (no keywords, or a keyword isn't plain printable ASCII)."""
    kws = sorted({k.lower() for k in keywords if k}, key=len, reverse=True)
    if not kws or not all(0x20 <= ord(c) <= 0x7E for k in kws for c in k):
        return None
    return (re.compile(b"|".join(re.escape(k.encode()) for k in kws)),
            re.compile(b"|".join(re.escape(k.encode("utf-16le")) for k in kws)))


def _is_printable_at(data, i, step):
    """Printable ASCII byte at i (step 1), or a printable char + NUL pair (step 2)."""
    return 0x20 <= data[i] <= 0x7E and (step == 1 or data[i + 1] == 0)


def _expand_to_string(data, start, end, step):
    """Grow a keyword hit left and right to the whole printable string around it."""
    lo, hi = start, end
    while lo - step >= 0 and start - lo < MAX_CONTEXT and _is_printable_at(data, lo - step, step):
        lo -= step
    while hi + step <= len(data) and hi - end < MAX_CONTEXT and _is_printable_at(data, hi, step):
        hi += step
    return lo, hi


def find_keyword_strings(data, matchers, kw_regex, min_len):
    """Yield (offset, text, encoding) for each string that contains a keyword."""
    low = data.lower()
    for pattern, codec, step, label in ((matchers[0], "ascii", 1, "ascii"),
                                        (matchers[1], "utf-16le", 2, "utf16")):
        covered_until = -1
        for m in pattern.finditer(low):
            if m.start() < covered_until:        # same string as the previous hit
                continue
            lo, hi = _expand_to_string(data, m.start(), m.end(), step)
            covered_until = hi
            if (hi - lo) // step < min_len:      # too short to count as a string
                continue
            text = data[lo:hi].decode(codec)
            if kw_regex.search(text):
                yield lo, text, label


def scan_pid(pid, kw_regex, min_len, stop, q, dump_file, keywords=()):
    """Scan one process. Pushes ('hit', row) / ('progress', pct) onto q.

    Returns (strings_seen, hits). strings_seen is None on the keyword-only fast
    path, which skips listing every string (so there's no total to report)."""
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        q.put(("status", f"Could not open PID {pid} (error {ctypes.get_last_error()}). "
                         f"Try 'Run as admin'."))
        return 0, 0

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    max_chunk = 64 * 1024 * 1024
    seen_hits, seen_all = set(), set()      # seen_all stores hashes, not whole strings
    # Keyword-only scans (no "save all strings") can skip listing every string.
    fast = build_fast_matchers(keywords) if (kw_regex and dump_file is None) else None
    total_strings = None if fast else 0
    hits = 0

    try:
        regions = list(iter_regions(handle))
        if not regions:
            hint = (" This is 32-bit Python, which can't read a 64-bit game - install 64-bit "
                    "Python or use the 64-bit exe." if IS_32BIT_PYTHON else
                    " Try 'Run as admin', or the process may have just exited.")
            q.put(("status", f"No readable memory found in PID {pid}.{hint}"))
            return total_strings, hits
        total_bytes = sum(s for _, s in regions) or 1
        # Each read is a chunk plus overlap on both sides, never more than its region.
        buf = ctypes.create_string_buffer(
            min(max_chunk + 2 * CHUNK_OVERLAP, max(s for _, s in regions)))
        done_bytes = 0
        for base, size in regions:
            offset = 0
            while offset < size:
                if stop.is_set():
                    return total_strings, hits
                n = min(max_chunk, size - offset)
                # Read a little before and after the chunk so a string (or keyword) that
                # straddles a boundary is found whole. Only strings that START inside the
                # chunk proper are kept below, so nothing is reported twice.
                lead = min(CHUNK_OVERLAP, offset)
                tail = min(CHUNK_OVERLAP, size - offset - n)
                chunk_base = base + offset - lead
                data = read_chunk(handle, chunk_base, lead + n + tail, buf)
                offset += n
                done_bytes += n
                if not data:
                    continue
                if fast:
                    found = find_keyword_strings(data, fast, kw_regex, min_len)
                else:
                    found = [(m.start(), m.group().decode("ascii"), "ascii")
                             for m in ascii_re.finditer(data)]
                    found += [(m.start(), m.group().decode("utf-16le"), "utf16")
                              for m in utf16_re.finditer(data)]
                for off, text, enc in found:
                    if off < lead or off >= lead + n:
                        continue                  # belongs to the neighbouring chunk
                    if total_strings is not None:
                        total_strings += 1
                    addr = chunk_base + off
                    if dump_file is not None:
                        h = hash(text)
                        if h not in seen_all:
                            seen_all.add(h)
                            dump_file.write(f"0x{addr:016X}\t{enc}\t{redact_secrets(text)}\n")
                    m = kw_regex.search(text) if kw_regex else None
                    if m:
                        kw = m.group(0).lower()
                        key = (kw, text)
                        if key in seen_hits:
                            continue
                        seen_hits.add(key)
                        hits += 1
                        q.put(("hit", (datetime.now().strftime("%H:%M:%S"), pid,
                                       f"0x{addr:016X}", enc, kw, redact_secrets(text))))
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
    if not snap or snap == INVALID_HANDLE_VALUE:
        return None
    modules = []
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
    try:
        ok = kernel32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            modules.append({
                "name": entry.szModule,
                "path": entry.szExePath,
                "base": ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0,
                "size": entry.modBaseSize,
            })
            ok = kernel32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return modules


def is_system_module_path(path):
    return is_under(path, os.environ.get("WINDIR", r"C:\Windows"))


def get_process_exe_dir(pid):
    if not psutil:
        return ""
    try:
        return os.path.dirname(psutil.Process(pid).exe())
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


def _listdir_safe(path):
    try:
        return os.listdir(path)
    except OSError:                       # PermissionError is a subclass
        return []


def enumerate_recycle_bin(stop=None):
    """Return dicts describing deleted files found in every drive's $Recycle.Bin,
    newest first."""
    results = []
    for drive in list_drives():
        if stop is not None and stop.is_set():
            break
        rb_path = os.path.join(drive, "$Recycle.Bin")
        for sid in _listdir_safe(rb_path):
            sid_path = os.path.join(rb_path, sid)
            for fn in _listdir_safe(sid_path):
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
    candidates = [_u32(data, off) for off in PF_RUN_COUNT_OFFSETS.get(version, ())
                  if off + 4 <= len(data)]
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


def _prefetch_entry(fn):
    """One prefetch row for the .pf file called fn, or None if it can't be stat'ed."""
    path = os.path.join(PREFETCH_DIR, fn)
    try:
        st = os.stat(path)
    except OSError:
        return None
    name_part = fn[:-3]
    prog, _, hash_part = name_part.rpartition("-")
    info = {
        "program": prog or name_part,
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
        info.update(version=parsed["version"], run_times=parsed["run_times"],
                    last_run=parsed["run_times"][0] if parsed["run_times"] else None,
                    run_count=parsed["run_count"], parsed=True)
    except Exception as exc:
        info["error"] = str(exc)
    return info


def enumerate_prefetch():
    names = [fn for fn in _listdir_safe(PREFETCH_DIR) if fn.lower().endswith(".pf")]
    results = [r for r in map(_prefetch_entry, names) if r]
    results.sort(key=lambda r: r["last_run"] or r["last_run_fs"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Process timeline
# ---------------------------------------------------------------------------
def list_java_candidates():
    """Return [(pid, name, create_time), ...] for running processes that look
    java/Minecraft-related, oldest first - the pool to pick a reference process from."""
    if not psutil:
        return []
    out = []
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        name = p.info["name"] or ""
        if any(h in name.lower() for h in MC_NAME_HINTS):
            out.append((p.info["pid"], name, p.info["create_time"]))
    return sorted(out, key=lambda r: r[2])


def find_reference_process_start():
    """Best-effort: earliest start time among processes that look Minecraft-related."""
    candidates = list_java_candidates()
    return candidates[0][2] if candidates else None


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
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i)) as sub:
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
HOSTS_DEFAULT = "default (localhost)"


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
        parts = raw.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for host in parts[1:]:
            if host.lower() == "localhost":
                kind = HOSTS_DEFAULT
            elif ip in LOOPBACK_IPS:
                kind = "blocks (points to loopback)"
            else:
                kind = "redirects to another IP"
            note = "" if kind == HOSTS_DEFAULT else hosts_note_for(host)
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


def find_dirs(root, names, max_depth=6):
    """One walk of root -> {name: [matching dirs]} for each name (case-insensitive).
    Searching for several folder names in a single walk is much cheaper than
    walking the whole launcher folder once per name."""
    wanted = {n.lower() for n in names}
    found = {n: [] for n in wanted}
    for dirpath, _dn, _fn in _walk_with_depth_limit(root, max_depth, HEAVY_DIRS - wanted):
        base = os.path.basename(dirpath).lower()
        if base in found:
            found[base].append(dirpath)
    return found


def find_dirs_named(root, name, max_depth=6):
    return find_dirs(root, [name], max_depth)[name.lower()]


def find_files_named(root, filename, max_depth=6):
    name_l = filename.lower()
    return [os.path.join(dirpath, fn)
            for dirpath, _dn, filenames in _walk_with_depth_limit(root, max_depth, HEAVY_DIRS)
            for fn in filenames if fn.lower() == name_l]


# ---------------------------------------------------------------------------
# Mods folder scanning (profile/instance-aware)
# ---------------------------------------------------------------------------
HASH_SIZE_CAP = 20 * 1024 * 1024      # mod jars bigger than this aren't hashed
VERSION_HASH_CAP = 64 * 1024 * 1024   # game-version jars are bigger, allow more
JAR_SUFFIXES = (".jar", ".jar.disabled")
MODS_SUBFOLDER_DEPTH = 1              # also look in mods\<mc version>\ (Forge style)
MAX_FLAG_WORDS = 6                    # keep the Flags column readable
JAR_WORKERS = min(8, os.cpu_count() or 4)   # jars are opened + hashed in parallel

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


def keyword_hits_in(text, matcher):
    """{keyword: tier} for every keyword whose normalised form occurs in text."""
    blob = _norm(text)
    return {kw: tier for key, (kw, tier) in matcher if key in blob}


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

    out = []
    for n in found:
        if isinstance(n, str) and n.strip() and n.strip() not in out:
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
    candidates = [c for c in (*names, os.path.basename(path), result["info"], *extra_text) if c]
    hits = keyword_hits_in("\x00".join(candidates), matcher)
    result["hits"] = hits
    evidence = []
    for kw in sorted(hits, key=lambda k: (-SEVERITY_RANK[hits[k]], k)):
        key = _norm(kw)
        for cand in candidates:
            if key in _norm(cand):
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
            for chunk in iter(lambda: f.read(1 << 20), b""):
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


def profile_label_for(found_dir, root):
    """Best-effort instance/profile name: the folder just above the found dir,
    falling back further up if that's the launcher root itself."""
    label = os.path.basename(os.path.dirname(found_dir))
    root_name = os.path.basename(root.rstrip("\\/"))
    if not label or label.lower() == root_name.lower():
        return "(default/global)"
    return label


def list_jars(mods_dir, matcher=(), subfolder_depth=MODS_SUBFOLDER_DEPTH):
    """Every .jar / .jar.disabled in a mods folder, including one level of
    subfolders (mods\\1.12.2\\foo.jar). Each row is a describe_jar() dict.
    Jars are opened and hashed on a small thread pool (zlib and hashlib release
    the GIL), which is the slow part for big mod packs."""
    paths = []
    pending = deque([(mods_dir, 0)])
    while pending:
        folder, depth = pending.popleft()
        try:
            with os.scandir(folder) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if depth < subfolder_depth:
                    pending.append((entry.path, depth + 1))
            elif entry.name.lower().endswith(JAR_SUFFIXES):
                paths.append(entry.path)
    if not paths:
        return []
    with ThreadPoolExecutor(max_workers=JAR_WORKERS) as pool:
        rows = pool.map(lambda p: describe_jar(p, os.path.relpath(p, mods_dir), matcher), paths)
        return [r for r in rows if r]


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
        hits = keyword_hits_in("\x00".join(extra), matcher)
        results.append({"kind": "version", "file": name, "path": folder, "size": 0,
                        "modified": _mtime(folder) or datetime.min, "sha256": "",
                        "info": "; ".join(bits) or "(no jar)",
                        "flags": format_flags(hits), "severity": worst_tier(hits),
                        "evidence": "; ".join(f"{k}: {name}" for k in sorted(hits))[:200]})
    return results


def scan_mods(roots, tiers=None, include_versions=True, stop=None, progress_cb=None):
    """roots: [(label, path), ...]; tiers: {keyword: 'high'|'context'}.
    Returns a flat list of rows, flagged ones first, each tagged with its
    launcher and profile/instance."""
    matcher = build_keyword_matcher(tiers or {})
    kinds = ("mods", "versions") if include_versions else ("mods",)
    jobs, seen = [], set()
    for label, root in roots:
        found = find_dirs(root, kinds)       # one walk finds both folder types
        for kind in kinds:
            for d in found[kind]:
                key = (kind, os.path.normcase(os.path.abspath(d)))
                if key not in seen:          # overlapping custom + default roots
                    seen.add(key)
                    jobs.append((kind, label, root, d))
    total = len(jobs) or 1
    rows = []
    for i, (kind, label, root, folder) in enumerate(jobs):
        if stop is not None and stop.is_set():
            break
        profile = profile_label_for(folder, root)
        found_rows = list_jars(folder, matcher) if kind == "mods" else list_versions(folder, matcher)
        for row in found_rows:
            row.update(launcher=label, profile=profile, mods_dir=folder)
            rows.append(row)
        if progress_cb:
            progress_cb((i + 1) * 100 / total)
    rows.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], r["launcher"].lower(),
                             r["profile"].lower(), r["kind"], r["file"].lower()))
    return rows


# ---------------------------------------------------------------------------
# Shared helpers for the version / crash-report audits
# ---------------------------------------------------------------------------
# JVM options that load code from outside the game's own jars. Plenty of legitimate
# software uses some of these (Lunar's own agent, profilers), so a hit is a lead.
SUSPICIOUS_JVM_ARGS = ("-javaagent", "-agentlib", "-agentpath", "-Xbootclasspath", "-noverify",
                       "-Xverify:none", "-Djava.system.class.loader", "--patch-module")
_SUSPICIOUS_LOWER = tuple(a.lower() for a in SUSPICIOUS_JVM_ARGS)

# Launch lines and crash logs can contain the player's session token. It is never
# displayed or exported: anything that looks like one is replaced before it is shown.
_SECRET_ARG_RE = re.compile(
    r"(--(?:accessToken|session|xuid|clientId|userProperties)(?:=|\s+))\S+", re.I)
# Older game versions log "Session ID is token:<token>:<uuid>"; JWT-shaped values are
# caught too, wherever they turn up (memory strings, crash reports, logs).
_TOKEN_RE = re.compile(r"(token:)[\w.\-]+|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}", re.I)


def redact_secrets(text):
    text = _SECRET_ARG_RE.sub(r"\1<hidden>", text)
    return _TOKEN_RE.sub(lambda m: (m.group(1) or "") + "<hidden>", text)


def csv_safe(value):
    """Stop spreadsheet apps from running text taken from the inspected PC as a
    formula (cells starting with = + - @)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def get_log_dir():
    """APP_DIR/logs if it can be written to, else a folder in the temp directory
    (the tool may be run from a read-only location or a locked-down USB stick).
    Returns None if neither works."""
    for base, name in ((APP_DIR, "logs"), (tempfile.gettempdir(), "ScarfSSTool_logs")):
        path = os.path.join(base, name)
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write_test")   # os.access() is unreliable on Windows
            with open(probe, "w"):
                pass
            os.remove(probe)
            return path
        except OSError:
            continue
    return None


def find_suspicious_jvm_args(args):
    """args: iterable of JVM option strings -> the ones worth a look (redacted)."""
    return [redact_secrets(a)[:200] for a in args if a.lower().startswith(_SUSPICIOUS_LOWER)]


def parse_iso_utc(text):
    """'2024-05-05T12:34:56.000Z' (UTC) -> naive local datetime, or None."""
    try:
        return (datetime.strptime(str(text)[:19], "%Y-%m-%dT%H:%M:%S")
                .replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None))
    except (ValueError, OSError, OverflowError):
        return None


def _compose_flags(notes, hits):
    """notes: [(tier, text)], hits: {keyword: tier} -> (flags text, worst tier).
    Strongest findings come first."""
    items = list(notes)
    if hits:
        items.append((worst_tier(hits), format_flags(hits)))
    items.sort(key=lambda n: -SEVERITY_RANK[n[0]])
    severity = items[0][0] if items else ""
    return " | ".join(text for _tier, text in items), severity


def _keyword_hits_in_text(text, matcher):
    """Keyword hits in free text (crash logs). Returns ({kw: tier}, evidence str).
    Matching ignores case and spaces/_/- so 'kill aura' also finds KillAura."""
    hits, lines = {}, {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("java_command"):
            continue
        norm = _norm(stripped)
        for key, (kw, tier) in matcher:
            if key in norm:
                hits[kw] = tier
                lines.setdefault(kw, redact_secrets(stripped)[:160])
    evidence = [f"{kw}: {lines[kw]}"
                for kw in sorted(hits, key=lambda k: (-SEVERITY_RANK[hits[k]], k))[:5]]
    return hits, "; ".join(evidence)


def _scan_progress(i, total, stop, progress_cb):
    """Report progress after item i; returns True if the scan should stop."""
    if progress_cb:
        progress_cb((i + 1) * 100 / total)
    return stop is not None and stop.is_set()


# ---------------------------------------------------------------------------
# Version folder audit (versions\<name>\ plus launcher_profiles.json)
# ---------------------------------------------------------------------------
# Main classes used by the stock launcher and the common loaders. Anything else is
# worth a look (custom clients often ship their own entry point).
KNOWN_MAIN_CLASS_PREFIXES = ("net.minecraft.", "net.fabricmc.", "org.quiltmc.", "cpw.mods.",
                             "net.minecraftforge.", "net.neoforged.", "com.mojang.")
VERSION_JSON_LIMIT = 2 * 1024 * 1024


def _flatten_json_args(items):
    """Version-json 'arguments' lists mix plain strings with {rules, value} objects."""
    out = []
    for item in items or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            value = item.get("value")
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, list):
                out.extend(v for v in value if isinstance(v, str))
    return out


def sha1_of(path, stop=None):
    """SHA-1 of a file (what Mojang publishes for client jars); None if stopped/unreadable."""
    h = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                if stop is not None and stop.is_set():
                    return None
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _check_jar_integrity(jar_path, meta, stop):
    """Compare a version jar with the official client size/SHA-1 Mojang records in
    the version json. Returns (status text, notes, evidence lines)."""
    size = os.stat(jar_path).st_size
    downloads = meta.get("downloads")
    client = downloads.get("client") if isinstance(downloads, dict) else None
    want_sha1 = client.get("sha1") if isinstance(client, dict) else None
    want_size = client.get("size") if isinstance(client, dict) else None
    if not (isinstance(want_sha1, str) and want_sha1):
        return "not checkable", [], []
    if isinstance(want_size, int) and want_size != size:
        return ("DIFFERS", [("high", f"jar is {size:,} bytes, official is {want_size:,}")],
                [f"Official size {want_size:,} bytes; actual {size:,} bytes."])
    if size > VERSION_HASH_CAP:
        return "too large to hash", [], []
    actual = sha1_of(jar_path, stop)
    if actual is None:
        return "not checked", [], []
    if actual.lower() == want_sha1.lower():
        return "matches official", [], []
    return ("DIFFERS", [("high", "jar SHA-1 differs from the official value in its own json")],
            [f"Expected SHA-1 {want_sha1}; actual {actual}."])


def audit_version_folder(folder, launcher, profile, matcher, stop=None):
    """One row for versions\\<name>\\, or None if the folder isn't a version folder."""
    name = os.path.basename(folder)
    json_path = os.path.join(folder, name + ".json")
    jar_path = os.path.join(folder, name + ".jar")
    has_json, has_jar = os.path.isfile(json_path), os.path.isfile(jar_path)
    if not (has_json or has_jar):
        return None

    notes, evidence = [], []
    meta = {}
    if has_json:
        parsed = _json_loads(_read_file_head(json_path, VERSION_JSON_LIMIT))
        if isinstance(parsed, dict):
            meta = parsed
        else:
            notes.append(("context", "version json can't be read"))
    else:
        notes.append(("context", "no version json"))

    vid = str(meta.get("id") or "")
    inherits = str(meta.get("inheritsFrom") or "")
    main = str(meta.get("mainClass") or "")
    if vid and vid != name:
        notes.append(("context", f"json id '{vid}' doesn't match the folder name"))
    if meta and not has_jar and not inherits:
        notes.append(("context", "no jar and no inheritsFrom"))
    if main and not main.startswith(KNOWN_MAIN_CLASS_PREFIXES):
        notes.append(("context", f"unrecognized main class: {main}"))

    arguments = meta.get("arguments")
    jvm_args = _flatten_json_args(arguments.get("jvm")) if isinstance(arguments, dict) else []
    for arg in find_suspicious_jvm_args(jvm_args)[:3]:
        notes.append(("context", f"JVM arg: {arg[:80]}"))
        evidence.append(f"JVM argument in the version json: {arg}")

    size, integrity = None, "not checkable"
    if has_jar:
        size = os.stat(jar_path).st_size
        integrity, int_notes, int_evidence = _check_jar_integrity(jar_path, meta, stop)
        notes += int_notes
        evidence += int_evidence

    # Keyword check (same tiers as the Mods Scanner): folder name, json fields, jar contents.
    extra = [name, vid, inherits, main]
    if has_jar:
        info = inspect_jar(jar_path, matcher, extra)
        hits, kw_evidence = info["hits"], info["evidence"]
        if info["note"]:
            notes.append(("context", info["note"]))
    else:
        hits = keyword_hits_in("\x00".join(x for x in extra if x), matcher)
        kw_evidence = "; ".join(f"{k}: {name}" for k in sorted(hits))
    if kw_evidence:
        evidence.append("Keyword evidence: " + kw_evidence)

    flags, severity = _compose_flags(notes, hits)
    return {"kind": "version", "file": name, "launcher": launcher, "profile": profile,
            "path": folder, "inherits": inherits, "main_class": main, "size": size,
            "modified": _mtime(jar_path if has_jar else json_path) or datetime.min,
            "integrity": integrity, "flags": flags, "severity": severity,
            "evidence": "\n".join(evidence)}


def audit_launcher_profiles(path, launcher, matcher):
    """Rows for each profile in launcher_profiles.json (Java arguments / custom Java)."""
    data = _json_loads(_read_file_head(path, 4 * 1024 * 1024))
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict):
        return []
    file_time = _mtime(path) or datetime.min
    rows = []
    for key, prof in profiles.items():
        if not isinstance(prof, dict):
            continue
        name = str(prof.get("name") or key)
        version_id = str(prof.get("lastVersionId") or "")
        java_args = str(prof.get("javaArgs") or "")
        java_dir = str(prof.get("javaDir") or "")
        game_dir = str(prof.get("gameDir") or "")
        notes = [("context", f"JVM arg: {arg[:80]}")
                 for arg in find_suspicious_jvm_args(java_args.split())[:3]]
        if java_dir:
            notes.append(("context", f"custom Java executable: {java_dir[:80]}"))
        hits = keyword_hits_in(
            "\x00".join(x for x in (name, version_id, java_args, java_dir, game_dir) if x), matcher)
        evidence = []
        if java_args:
            evidence.append(f"javaArgs: {redact_secrets(java_args)[:400]}")
        if java_dir:
            evidence.append(f"javaDir: {java_dir}")
        if game_dir:
            evidence.append(f"gameDir: {game_dir}")
        flags, severity = _compose_flags(notes, hits)
        rows.append({"kind": "profile", "file": name, "launcher": launcher, "profile": "",
                     "path": path, "inherits": version_id, "main_class": "", "size": None,
                     "modified": parse_iso_utc(prof.get("lastUsed")) or file_time,
                     "integrity": "-", "flags": flags, "severity": severity,
                     "evidence": "\n".join(evidence)})
    return rows


def scan_versions(roots, tiers=None, stop=None, progress_cb=None):
    """roots: [(label, path), ...] -> rows, flagged ones first."""
    matcher = build_keyword_matcher(tiers or {})
    jobs, seen = [], set()

    def claim(path):
        key = os.path.normcase(os.path.abspath(path))
        if key in seen:
            return False
        seen.add(key)
        return True

    for label, root in roots:
        for vdir in find_dirs_named(root, "versions"):
            if not claim(vdir):
                continue
            profile = profile_label_for(vdir, root)
            for sub in sorted(_listdir_safe(vdir)):
                folder = os.path.join(vdir, sub)
                if os.path.isdir(folder):
                    jobs.append(("version", label, profile, folder))
        profiles_json = os.path.join(root, "launcher_profiles.json")
        if os.path.isfile(profiles_json) and claim(profiles_json):
            jobs.append(("profiles", label, "", profiles_json))

    rows = []
    total = len(jobs) or 1
    for i, (kind, label, profile, target) in enumerate(jobs):
        if kind == "version":
            row = audit_version_folder(target, label, profile, matcher, stop)
            if row:
                rows.append(row)
        else:
            rows.extend(audit_launcher_profiles(target, label, matcher))
        if _scan_progress(i, total, stop, progress_cb):
            break
    rows.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], r["launcher"].lower(),
                             r["kind"], r["file"].lower()))
    return rows


# ---------------------------------------------------------------------------
# Crash report audit (Minecraft crash-reports, JVM hs_err logs, Windows Error Reports)
# ---------------------------------------------------------------------------
CRASH_READ_CAP = 8 * 1024 * 1024
MAX_EVIDENCE_PATHS = 25
WER_LABEL_PREFIX = "Windows Error Reporting"
KIND_MC, KIND_HS, KIND_WER = "MC report", "hs_err", "WER"

# DLLs that legitimately live outside the usual folders (game natives, JNA, drivers).
BENIGN_DLL_PREFIXES = ("lwjgl", "jna", "glfw", "openal", "jemalloc", "freetype", "jinput", "sdl")
DLL_SUFFIXES = (".dll", ".asi", ".drv", ".ocx", ".ax")

_CRASH_NAME_TIME_RE = re.compile(r"crash-(\d{4})-(\d{2})-(\d{2})_(\d{2})\.(\d{2})\.(\d{2})")
_HS_LIB_RE = re.compile(r"^0x[0-9a-fA-F]+\s*-\s*0x[0-9a-fA-F]+\s+(\S.*?)\s*$")
_HS_FRAME_RE = re.compile(r"^#\s+[A-Za-z]\s+\[(.+?)(?:\+0x[0-9a-fA-F]+)?\]")


def get_default_crash_roots():
    """Launcher folders plus the two Windows Error Reporting stores."""
    roots = list(get_default_client_roots())
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append((WER_LABEL_PREFIX + " (user)", os.path.join(local, "Microsoft", "Windows", "WER")))
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    roots.append((WER_LABEL_PREFIX + " (system)", os.path.join(program_data, "Microsoft", "Windows", "WER")))
    return roots


def _trusted_dll_prefixes(java_home=""):
    env = os.environ
    candidates = (env.get("WINDIR", r"C:\Windows"), env.get("ProgramFiles", r"C:\Program Files"),
                  env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), java_home)
    return tuple(_win_norm(c).rstrip("\\") + "\\" for c in candidates if c)


def untrusted_dlls(paths, java_home=""):
    """DLLs outside Windows / Program Files / the Java install (minus known natives)."""
    prefixes = _trusted_dll_prefixes(java_home)
    out = []
    for p in paths:
        norm = _win_norm(p)
        if not norm.endswith(DLL_SUFFIXES):
            continue
        if norm.startswith(prefixes) or _win_basename(norm).startswith(BENIGN_DLL_PREFIXES):
            continue
        out.append(p)
    return out


def _dll_findings(untrusted, crashed_module=""):
    """-> (notes, evidence lines) for a list of untrusted DLL paths."""
    if not untrusted:
        return [], []
    names = [_win_basename(p) for p in untrusted]
    shown = ", ".join(names[:3]) + (f", +{len(names) - 3} more" if len(names) > 3 else "")
    notes = [("context", f"{len(names)} DLL(s) outside system/Java folders: {shown}")]
    evidence = ["DLLs outside Windows / Program Files / Java folders:"]
    evidence += [f"  {p}" for p in untrusted[:MAX_EVIDENCE_PATHS]]
    if len(untrusted) > MAX_EVIDENCE_PATHS:
        evidence.append(f"  ... and {len(untrusted) - MAX_EVIDENCE_PATHS} more")
    if crashed_module and any(n.lower() == crashed_module.lower() for n in names):
        notes.insert(0, ("context", f"crashed inside {crashed_module}, which is outside system/Java folders"))
    return notes, evidence


def read_text_capped(path):
    with open(path, "rb") as f:
        raw = f.read(CRASH_READ_CAP)
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):          # Report.wer is UTF-16
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def analyze_mc_crash(text, filename):
    """Minecraft crash-reports\\crash-*.txt -> (summary, jvm flags, time or None)."""
    lines = text.splitlines()
    description = exception = ""
    for i, ln in enumerate(lines):
        if ln.startswith("Description:"):
            description = ln.split(":", 1)[1].strip()
            for nxt in lines[i + 1:i + 8]:
                s = nxt.strip()
                if s and not s.startswith("at "):
                    exception = s
                    break
            break
    jvm_flags = []
    for ln in lines:
        s = ln.strip()
        if s.startswith("JVM Flags:"):
            jvm_flags = s.split(";", 1)[1].split() if ";" in s else []
            break
    when = None
    m = _CRASH_NAME_TIME_RE.search(filename)
    if m:
        try:
            when = datetime(*map(int, m.groups()))
        except ValueError:
            when = None
    summary = description + (f" - {exception[:100]}" if exception else "")
    return summary, jvm_flags, when


def analyze_hs_err(text):
    """JVM fatal-error log -> (summary, crashing module, jvm args, loaded library paths)."""
    lines = text.splitlines()
    summary = problem = ""
    jvm_args, libs = [], []
    for i, ln in enumerate(lines):
        if not summary and "A fatal error has been detected" in ln:
            for nxt in lines[i + 1:i + 6]:
                s = nxt.lstrip("#").strip()
                if s:
                    summary = re.split(r"\s+at pc=", s)[0][:140]
                    break
        elif ln.startswith("# Problematic frame:") and i + 1 < len(lines):
            m = _HS_FRAME_RE.match(lines[i + 1])
            if m:
                problem = m.group(1)
        elif ln.startswith("jvm_args:"):
            jvm_args = ln.split(":", 1)[1].split()
        else:
            m = _HS_LIB_RE.match(ln)
            if m:
                libs.append(m.group(1))
    return summary, problem, jvm_args, libs


def parse_wer(text):
    """Report.wer -> (key/value dict, loaded module paths, fault module name)."""
    kv, modules = {}, []
    for ln in text.splitlines():
        key, sep, value = ln.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key.startswith("LoadedModule["):
            modules.append(value)
        else:
            kv.setdefault(key, value)
    fault = ""
    for key, value in kv.items():
        m = re.match(r"Sig\[(\d+)\]\.Name$", key)
        if m and value.lower() == "fault module name":
            fault = kv.get(f"Sig[{m.group(1)}].Value", "")
            break
    return kv, modules, fault


def audit_crash_file(label, kind, path, matcher):
    """One row for a crash file, or None if it isn't relevant (non-Java WER report)."""
    try:
        text = read_text_capped(path)
    except OSError as exc:
        return {"time": _mtime(path) or datetime.min, "kind": kind, "launcher": label,
                "file": os.path.basename(path), "path": path, "summary": "",
                "flags": f"couldn't read file: {exc}", "severity": "context", "evidence": ""}

    notes, evidence = [], []
    when, summary = None, ""
    if kind == KIND_MC:
        summary, jvm_flags, when = analyze_mc_crash(text, os.path.basename(path))
        notes += [("context", f"JVM flag: {arg[:80]}")
                  for arg in find_suspicious_jvm_args(jvm_flags)[:3]]
    elif kind == KIND_HS:
        summary, problem, jvm_args, libs = analyze_hs_err(text)
        notes += [("context", f"JVM arg: {arg[:80]}")
                  for arg in find_suspicious_jvm_args(jvm_args)[:3]]
        exe = next((p for p in libs if _win_norm(p).endswith(("\\javaw.exe", "\\java.exe"))), "")
        java_home = _win_dirname(_win_dirname(exe)) if exe else ""
        dll_notes, dll_evidence = _dll_findings(untrusted_dlls(libs, java_home), problem)
        notes += dll_notes
        evidence += dll_evidence
    else:
        kv, modules, fault = parse_wer(text)
        app = kv.get("AppName", "")
        if not any(h in (app + " " + kv.get("AppPath", "")).lower() for h in MC_NAME_HINTS):
            return None
        try:
            when = filetime_to_datetime(int(kv.get("EventTime", "0")))
        except ValueError:
            when = None
        summary = f"{app} - {kv.get('FriendlyEventName') or kv.get('EventType', 'crash')}"
        if fault:
            summary += f", fault module {fault}"
        exe = kv.get("AppPath", "")
        java_home = _win_dirname(_win_dirname(exe)) if exe else ""
        dll_notes, dll_evidence = _dll_findings(untrusted_dlls(modules, java_home), fault)
        notes += dll_notes
        evidence += dll_evidence

    hits, kw_evidence = _keyword_hits_in_text(text, matcher)
    if kw_evidence:
        evidence.insert(0, "Keyword evidence: " + kw_evidence)
    flags, severity = _compose_flags(notes, hits)
    return {"time": when or _mtime(path) or datetime.min, "kind": kind, "launcher": label,
            "file": os.path.basename(path), "path": path, "summary": summary[:200],
            "flags": flags, "severity": severity, "evidence": "\n".join(evidence)}


def scan_crash_reports(roots, tiers=None, stop=None, progress_cb=None):
    """roots: [(label, path), ...] -> rows, flagged ones first, newest first."""
    matcher = build_keyword_matcher(tiers or {})
    files, seen = [], set()

    def add(label, kind, path):
        key = os.path.normcase(os.path.abspath(path))
        if key not in seen:
            seen.add(key)
            files.append((label, kind, path))

    walk_prune = HEAVY_DIRS - {"crash-reports"}
    for label, root in roots:
        if label.startswith(WER_LABEL_PREFIX):
            for dirpath, _dn, filenames in _walk_with_depth_limit(root, 4):
                for fn in filenames:
                    if fn.lower() == "report.wer":
                        add(label, KIND_WER, os.path.join(dirpath, fn))
            continue
        for dirpath, _dn, filenames in _walk_with_depth_limit(root, 6, walk_prune):
            in_crash_dir = os.path.basename(dirpath).lower() == "crash-reports"
            for fn in filenames:
                low = fn.lower()
                if in_crash_dir and low.endswith((".txt", ".log")):
                    add(label, KIND_MC, os.path.join(dirpath, fn))
                elif low.startswith("hs_err_pid") and low.endswith(".log"):
                    add(label, KIND_HS, os.path.join(dirpath, fn))

    rows = []
    total = len(files) or 1
    for i, (label, kind, path) in enumerate(files):
        row = audit_crash_file(label, kind, path, matcher)
        if row:
            rows.append(row)
        if _scan_progress(i, total, stop, progress_cb):
            break
    # flagged first, then newest first
    rows.sort(key=lambda r: (-SEVERITY_RANK[r["severity"]], -r["time"].timestamp()
                             if r["time"] > datetime.min else 0))
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

    def _unpack(self, fmt):
        return struct.unpack(fmt, self._read(struct.calcsize(fmt)))[0]

    def read_string(self):
        return self._read(self._unpack(">H")).decode("utf-8", errors="replace")

    def read_payload(self, tag_type):
        scalar = {1: ">b", 2: ">h", 3: ">i", 4: ">q", 5: ">f", 6: ">d"}.get(tag_type)
        if scalar:
            return self._unpack(scalar)
        if tag_type == 7:                                   # byte array
            return self._read(max(self._unpack(">i"), 0))
        if tag_type == 8:
            return self.read_string()
        if tag_type == 9:                                   # list
            item_type = self._unpack(">b")
            n = self._unpack(">i")
            if item_type == 0 or n <= 0:
                return []
            return [self.read_payload(item_type) for _ in range(n)]
        if tag_type == 10:                                  # compound
            compound = {}
            while True:
                t = self._unpack(">b")
                if t == 0:
                    break
                name = self.read_string()
                compound[name] = self.read_payload(t)
            return compound
        if tag_type in (11, 12):                            # int array / long array
            item = ">i" if tag_type == 11 else ">q"
            return [self._unpack(item) for _ in range(max(self._unpack(">i"), 0))]
        raise ValueError(f"unknown NBT tag type {tag_type}")

    def read_root(self):
        t = self._unpack(">b")
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
    return [{"name": s.get("name", ""), "ip": s.get("ip", "")}
            for s in root.get("servers") or [] if isinstance(s, dict)]


def scan_servers(roots, max_depth=6):
    """roots: [(label, path), ...]. Returns rows: launcher, profile, name, ip, source file."""
    rows, seen = [], set()
    for label, root in roots:
        for dat_path in find_files_named(root, "servers.dat", max_depth):
            key = os.path.normcase(os.path.abspath(dat_path))
            if key in seen:
                continue
            seen.add(key)
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

# Cheap pre-check run on every log line: most lines can't match any pattern above,
# so they're skipped before the heavier regexes run (~11x faster on big logs).
# KEEP IN SYNC: if you add a pattern to LOG_LINE_PATTERNS, add its key phrase here.
LOG_TRIGGER_RE = re.compile(
    r"joined the game|left the game|UUID of player|logged in|"
    r"has made the advancement|has completed the challenge|has reached the goal|"
    r"<[A-Za-z0-9_]{3,16}>|Setting user:")
LOG_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


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


def _safe_mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def log_file_date(path, mtime=None):
    """'YYYY-MM-DD' for a log file: from its name (2025-03-01-2.log.gz), otherwise
    from its modified time (latest.log and client-specific names)."""
    m = LOG_DATE_RE.match(os.path.basename(path))
    if m:
        return m.group(1)
    mt = _safe_mtime(path) if mtime is None else mtime
    return datetime.fromtimestamp(mt).strftime("%Y-%m-%d") if mt else ""


def iter_log_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, filenames in os.walk(root):     # os.walk on a non-dir yields nothing
        for fn in filenames:
            if fn.endswith((".log", ".log.gz")):
                yield os.path.join(dirpath, fn)


def read_log_lines(path):
    """Yield a log file's lines one at a time (plain .log or gzipped .log.gz)."""
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
            yield from f
    except Exception:
        return


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
    keyed = []
    for f in files:                         # one stat per file, not one per sort comparison
        mt = _safe_mtime(f)
        keyed.append((log_file_date(f, mt), mt, f))
    keyed.sort()
    total = len(keyed) or 1
    for i, (day, _mt, path) in enumerate(keyed):
        if stop is not None and stop.is_set():
            break
        base = os.path.basename(path)
        for line in read_log_lines(path):
            if not LOG_TRIGGER_RE.search(line):
                continue
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
#   3. Base classes:  TableTab -> ScanTab -> RootsScanTab -> AuditTab
#   4. The tabs themselves (most are ~20-40 lines because the base classes do
#      the UI building, background threading, filtering and exporting)
#   5. App window + theming
#
# To add a tab: subclass ScanTab (or RootsScanTab / AuditTab if it searches
# launcher folders), fill in the class attributes + hooks, and add one line to TABS.
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
    """Offer to relaunch elevated; only closes this window if the UAC prompt was accepted."""
    if messagebox.askyesno("Run as admin", "Restart this tool with administrator rights?"):
        if relaunch_as_admin():
            widget.winfo_toplevel().destroy()


def admin_status_label(parent):
    """'Running as admin' / 'Not admin' label."""
    ok = is_admin()
    return ttk.Label(parent, text="Running as admin" if ok else "Not admin",
                     foreground="green" if ok else "gray")


def shared_keyword_tiers(widget):
    """The Memory Scan tab's (possibly edited) keyword box, so there is one list to
    maintain; falls back to the defaults."""
    tiers = parse_keyword_lines(DEFAULT_KEYWORDS)
    mem = getattr(widget.winfo_toplevel(), "tabs", {}).get("Memory Scan")
    if mem is not None:
        tiers = mem.get_keywords() or tiers
    return tiers


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
        detail_text(row)        text for the details box (with HAS_DETAIL = True)
        row_tags(row)           ('high',) / ('context',) colours a row red / amber
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
    HAS_DETAIL = False        # True -> a read-only box under the table shows detail_text(row)
    DETAIL_HEIGHT = 5
    FILTER_DELAY_MS = 150

    def __init__(self, parent):
        super().__init__(parent, padding=self.PADDING)
        self.rows = []
        self.sort_col = None
        self.sort_reverse = False
        self._filter_job = None        # pending debounced filter refresh, if any
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

    def detail_text(self, row):
        return ""

    def row_tags(self, row):
        """Treeview tags for a row: 'high' / 'context' colour it (see _apply_theme)."""
        return ()

    def search_text(self, row):
        return " ".join(str(row[k]) for k in self.SEARCH_KEYS).lower()

    def is_visible(self, row, f):
        return not f or f in self.search_text(row)

    def sort_key(self, row, col):
        """Sort key for one cell. Tuples keep mixed types (None, numbers, dates, text)
        from ever being compared with each other."""
        v = row.get(col)
        if v is None:
            return (0, 0)
        if isinstance(v, (int, float)):
            return (1, v)
        if isinstance(v, datetime):
            return (2, v)
        return (3, str(v).lower())

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
        if self.HAS_DETAIL:
            self.tree.bind("<<TreeviewSelect>>", self.show_detail)
            self.detail = tk.Text(self, height=self.DETAIL_HEIGHT, wrap="word", state="disabled")
            self.detail.pack(fill="x", pady=(8, 0))

    def show_detail(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        visible = self.visible_rows()
        idx = self.tree.index(sel[0])
        if idx >= len(visible):
            return
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", self.detail_text(visible[idx]))
        self.detail.config(state="disabled")

    def add_filter_box(self, ctl):
        ttk.Label(ctl, text="Filter:").pack(side="left", padx=(20, 2))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.schedule_filter())
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

    def insert_row(self, row):
        self.tree.insert("", "end", values=self.row_values(row), tags=self.row_tags(row))

    def schedule_filter(self):
        """Rebuild the table once typing pauses, not on every keystroke."""
        if self._filter_job is not None:
            self.after_cancel(self._filter_job)
        self._filter_job = self.after(self.FILTER_DELAY_MS, self.apply_filter)

    def apply_filter(self):
        if self._filter_job is not None:
            self.after_cancel(self._filter_job)
            self._filter_job = None
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

    def build_extra_controls(self, ctl):
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
            rows, msg = [], str(exc)
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


# ---------------------------------------------------------------------------
# Base class 3: RootsScanTab - a ScanTab that searches launcher folders
# Base class 4: AuditTab    - ... and flags rows against the keyword list
# ---------------------------------------------------------------------------
class RootsScanTab(ScanTab):
    """ScanTab with a 'Search locations' picker (launcher folders by default).
    prepare_scan() returns (roots,) - or (roots, keyword tiers) when USES_KEYWORDS."""

    PICKER_TITLE = "Search locations"
    PICKER_DEFAULT_CAPTION = "Default launcher folders (unchecked ones weren't found):"
    PICKER_CUSTOM_CAPTION = "Custom launcher/instance folder:"
    USES_KEYWORDS = False
    keyword_count = 0

    def picker_defaults(self):
        return get_default_client_roots()

    def build_top(self):
        self.picker = add_path_picker(
            self, self.PICKER_TITLE, defaults=self.picker_defaults(),
            default_caption=self.PICKER_DEFAULT_CAPTION,
            custom_caption=self.PICKER_CUSTOM_CAPTION)

    def keyword_tiers(self):
        return shared_keyword_tiers(self)

    def prepare_scan(self):
        roots = self.picker.selected()
        if not roots:
            messagebox.showwarning("No locations",
                                   "Select at least one default folder or add a custom one.")
            return None
        if not self.USES_KEYWORDS:
            return (roots,)
        tiers = self.keyword_tiers()
        self.keyword_count = len(tiers)
        return (roots, tiers)


class AuditTab(RootsScanTab):
    """Rows carry 'flags' / 'severity' / 'evidence'; red = high, amber = context."""

    USES_KEYWORDS = True
    HAS_PROGRESS = True
    SORTABLE = True
    HAS_DETAIL = True
    DESCENDING_COLS = ("flags",)        # columns whose first click sorts biggest-first

    def row_tags(self, r):
        return (r["severity"],) if r["severity"] else ()

    def sort_key(self, r, col):
        if col == "flags":
            return (SEVERITY_RANK[r["severity"]], r["flags"].lower())
        return super().sort_key(r, col)

    def sort_starts_descending(self, col):
        return col in self.DESCENDING_COLS

    def flag_summary(self, rows):
        high = sum(1 for r in rows if r["severity"] == "high")
        ctx = sum(1 for r in rows if r["severity"] == "context")
        return f"{high} red, {ctx} amber ({self.keyword_count} keywords checked)"


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
    HAS_DETAIL = True
    DETAIL_HEIGHT = 4

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

    def detail_text(self, row):
        _t, _pid, addr, enc, kw, text = row
        return f"{addr} [{enc}] kw='{kw}' ({self._tier(kw)})\n{text}"

    # ---- keywords ----------------------------------------------------------
    def get_keywords(self):
        """{keyword: 'high'|'context'} from the keyword box."""
        return parse_keyword_lines(self.kw_text.get("1.0", "end").splitlines())

    def load_keywords(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                    text = f.read()
            except OSError as exc:
                messagebox.showerror("Load keywords", f"Could not read that file:\n{exc}")
                return
            self.kw_text.delete("1.0", "end")
            self.kw_text.insert("1.0", text)

    def save_keywords(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(keyword_lines(self.get_keywords())))
            except OSError as exc:
                messagebox.showerror("Save keywords", f"Could not save that file:\n{exc}")

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
        log_dir = get_log_dir()
        dump_file = None
        summary = []
        try:
            if dump_all:
                if log_dir:
                    dump_file = open(os.path.join(log_dir, f"allstrings_{stamp}.txt"), "w",
                                     encoding="utf-8")
                else:
                    summary.append("no writable folder for the all-strings dump (skipped)")
            for pid in pids:
                if self.stop_event.is_set():
                    break
                self.q.put(("status", f"Scanning PID {pid}..."))
                total, hits = scan_pid(pid, kw_regex, min_len, self.stop_event, self.q,
                                       dump_file, keywords=self.kw_tiers)
                strings = "" if total is None else f"{total} strings, "
                summary.append(f"PID {pid}: {strings}{hits} matches")
        except Exception as exc:
            summary.append(f"Error: {exc}")
        finally:
            # Always tell the UI we're finished, even if setup or a scan failed -
            # otherwise the Start button would stay disabled forever.
            if dump_file:
                dump_file.close()
            self.q.put(("done", " | ".join(summary), stamp, log_dir))

    def _poll_queue(self):
        """Drain the worker's queue on the UI thread. Hits are inserted in one batch
        per poll, and the progress bar / status are only touched once each."""
        try:
            progress = status = done = None
            f = self.current_filter()
            try:
                while True:
                    msg = self.q.get_nowait()
                    kind = msg[0]
                    if kind == "hit":
                        self.rows.append(msg[1])
                        if self.is_visible(msg[1], f):
                            self.insert_row(msg[1])
                    elif kind == "progress":
                        progress = msg[1]
                    elif kind == "status":
                        status = msg[1]
                    elif kind == "done":
                        done = msg
            except queue.Empty:
                pass
            if progress is not None:
                self.progress["value"] = progress
            if status is not None:
                self.set_status(status)
            if done is not None:
                self._on_done(*done[1:])
        finally:
            # Reschedule no matter what, so one error can't freeze the tab for good.
            self.after(100, self._poll_queue)

    def _on_done(self, summary, stamp, log_dir):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        saved = "Log not saved (no writable folder)."
        if log_dir:
            log_path = os.path.join(log_dir, f"ss_log_{stamp}.txt")
            try:
                self._write_log(log_path)
                saved = f"Log saved: {log_path}"
            except OSError as exc:
                saved = f"Log not saved ({exc})."
        state = "Stopped" if self.stop_event.is_set() else "Done"
        self.set_status(f"{state}. {summary or 'No data.'}  {saved}")

    # ---- clear, export -----------------------------------------------------
    def clear_results(self):
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0

    def _write_log(self, path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            if path.lower().endswith(".csv"):
                w = csv.writer(f)
                w.writerow(self.EXPORT_HEADER + ["level"])
                w.writerows([csv_safe(c) for c in r] + [self._tier(r[4])] for r in self.rows)
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
            try:
                self._write_log(path)
            except OSError as exc:
                messagebox.showerror("Export", f"Could not write the file:\n{exc}")
                return
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
            elif is_under(m["path"], game_dir):
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
        return list(self.row_values(m))


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
        return list(self.row_values(r))


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
class ModsScannerTab(AuditTab):
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
    DESCENDING_COLS = ("flags", "size", "modified")
    DETAIL_HEIGHT = 4

    def build_top(self):
        super().build_top()
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

    def keyword_tiers(self):
        """The shared keyword list plus this scan's extra keywords."""
        tiers = super().keyword_tiers()
        for kw, tier in parse_keyword_lines(self.extra_kw.get().split(",")).items():
            if tiers.get(kw) != "high":
                tiers[kw] = tier
        return tiers

    def prepare_scan(self):
        args = super().prepare_scan()
        return None if args is None else (*args, self.include_versions.get())

    def scan(self, roots, tiers, include_versions):
        return scan_mods(roots, tiers, include_versions, self.stop_event, self.report_progress)

    def done_message(self, rows):
        mods = sum(1 for r in rows if r["kind"] == "mod")
        return (f"Found {mods} mod jar(s) and {len(rows) - mods} game version(s); "
                f"{self.flag_summary(rows)}.")

    def row_values(self, m):
        return (m["flags"], m["file"], m["info"], m["kind"], m["launcher"], m["profile"],
                m["size"], fmt_dt(m["modified"]), m["sha256"])

    def export_row(self, m):
        return [m["flags"], m["kind"], m["launcher"], m["profile"], m["file"], m["info"],
                m["size"], fmt_dt(m["modified"]), m["sha256"], m["evidence"], m["path"]]

    def detail_text(self, m):
        return (f"{m['path']}\n"
                f"Flags: {m['flags'] or 'none'}\n"
                f"Evidence: {m['evidence'] or '-'}\n"
                f"SHA-256: {m['sha256'] or '-'}")


# ---------------------------------------------------------------------------
# Versions Audit tab (installed game versions + launcher profiles)
# ---------------------------------------------------------------------------
class VersionsAuditTab(AuditTab):
    NOTE = ("Audits every installed game version (versions\\<name>\\) and every launcher profile. "
            "For vanilla versions the jar is compared with the official SHA-1 that Mojang records "
            "in the version's own json - a modified jar shows as DIFFERS (red). Amber flags are "
            "oddities worth a look: json id not matching the folder, a missing jar, an unfamiliar "
            "main class, or JVM options such as -javaagent / -Xbootclasspath in a version json or "
            "profile (some legitimate tools use these). Keywords come from the Memory Scan list. "
            "The official hash lives in a file the user could also edit, so treat it as a lead.")
    COLUMNS = (("flags", "Flags", 270), ("file", "Version / profile", 150), ("kind", "Kind", 55),
               ("integrity", "Official hash", 110), ("launcher", "Launcher", 90),
               ("inherits", "Inherits / uses", 90), ("main_class", "Main class", 190),
               ("size", "Jar size", 75), ("modified", "Modified / last used", 125))
    STRETCH = "flags"
    SEARCH_KEYS = ("flags", "file", "kind", "integrity", "launcher", "profile", "inherits", "main_class")
    EXPORT_HEADER = ["flags", "kind", "official_hash", "launcher", "profile", "name", "inherits_or_uses",
                     "main_class", "jar_size_bytes", "modified_or_last_used", "details", "full_path"]
    PICKER_CUSTOM_CAPTION = "Custom launcher/instance folder (or a versions folder itself):"
    SCAN_LABEL = "Scan versions"
    BUSY_TEXT = "Auditing version folders and launcher profiles..."
    ERROR_TITLE = "Versions audit failed"
    DESCENDING_COLS = ("flags", "size", "modified")

    def scan(self, roots, tiers):
        return scan_versions(roots, tiers, self.stop_event, self.report_progress)

    def done_message(self, rows):
        versions = sum(1 for r in rows if r["kind"] == "version")
        return (f"Checked {versions} version folder(s) and {len(rows) - versions} launcher profile(s); "
                f"{self.flag_summary(rows)}.")

    def row_values(self, r):
        return (r["flags"], r["file"], r["kind"], r["integrity"], r["launcher"], r["inherits"],
                r["main_class"], "-" if r["size"] is None else r["size"], fmt_dt(r["modified"]))

    def export_row(self, r):
        return [r["flags"], r["kind"], r["integrity"], r["launcher"], r["profile"], r["file"],
                r["inherits"], r["main_class"], "" if r["size"] is None else r["size"],
                fmt_dt(r["modified"]), r["evidence"], r["path"]]

    def detail_text(self, r):
        return (f"{r['path']}\nFlags: {r['flags'] or 'none'}\nOfficial hash: {r['integrity']}\n"
                f"{r['evidence'] or 'No further details.'}")


# ---------------------------------------------------------------------------
# Crash Reports tab (Minecraft crash reports, JVM hs_err logs, Windows Error Reports)
# ---------------------------------------------------------------------------
class CrashReportsTab(AuditTab):
    NOTE = ("Reads crash evidence already on disk: Minecraft's crash-reports folder, JVM fatal-error "
            "logs (hs_err_pid*.log) and Windows Error Reporting entries for java. A crash often "
            "names code that was injected into the game: the keyword list (from Memory Scan) is "
            "checked against the whole report, DLLs loaded from outside Windows / Program Files / "
            "the Java folder are listed (overlays and recorders show up here too), and suspicious "
            "JVM options are flagged. Session tokens in these files are never displayed or exported. "
            "The system-wide Windows Error Reporting folder needs admin rights to read.")
    COLUMNS = (("flags", "Flags", 300), ("time", "Time", 125), ("kind", "Type", 70),
               ("launcher", "Source", 115), ("file", "File", 210), ("summary", "Summary", 290))
    STRETCH = "summary"
    SEARCH_KEYS = ("flags", "file", "kind", "launcher", "summary")
    EXPORT_HEADER = ["flags", "time", "type", "source", "file", "summary", "details", "full_path"]
    PICKER_DEFAULT_CAPTION = "Default locations (unchecked ones weren't found):"
    PICKER_CUSTOM_CAPTION = ("Custom launcher/instance folder "
                             "(searched for crash-reports and hs_err files):")
    SCAN_LABEL = "Scan crash reports"
    BUSY_TEXT = "Reading crash reports..."
    ERROR_TITLE = "Crash report scan failed"
    DESCENDING_COLS = ("flags", "time")

    def picker_defaults(self):
        return get_default_crash_roots()

    def scan(self, roots, tiers):
        return scan_crash_reports(roots, tiers, self.stop_event, self.report_progress)

    def done_message(self, rows):
        return f"Found {plural(len(rows), 'crash report', 'crash reports')}; {self.flag_summary(rows)}."

    def row_values(self, r):
        return (r["flags"], fmt_dt(r["time"]), r["kind"], r["launcher"], r["file"], r["summary"])

    def export_row(self, r):
        return [r["flags"], fmt_dt(r["time"]), r["kind"], r["launcher"], r["file"], r["summary"],
                r["evidence"], r["path"]]

    def detail_text(self, r):
        return (f"{r['path']}\nFlags: {r['flags'] or 'none'}\nSummary: {r['summary'] or '-'}\n"
                f"{r['evidence'] or 'No further details.'}")


# ---------------------------------------------------------------------------
# Servers tab (recent/saved servers across launchers and profiles)
# ---------------------------------------------------------------------------
class ServersTab(RootsScanTab):
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

    def scan(self, roots):
        return scan_servers(roots)

    def done_message(self, rows):
        return f"Found {plural(len(rows), 'saved server entry', 'saved server entries')}."

    def row_values(self, r):
        return (r["launcher"], r["profile"], r["name"], r["ip"], r["source"])

    def export_row(self, r):
        return list(self.row_values(r))


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
        extra = [r for r in rows if r["kind"] != HOSTS_DEFAULT]
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
        for pid, name, ct in list_java_candidates():
            label = f"{name}  (PID {pid})  started {datetime.fromtimestamp(ct).strftime('%H:%M:%S')}"
            self.java_proc_map[label] = (pid, ct)
        labels = list(self.java_proc_map)
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
            try:
                seconds = max(2, int(self.interval.get()))
            except (ValueError, tk.TclError):      # box cleared / non-numeric mid-edit
                seconds = 5
            self.auto_job = self.after(seconds * 1000, self._auto_tick)


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

    ACCOUNT_COLUMNS = (("account", "Account", 170), ("sessions", "Launches", 70),
                       ("first_seen", "First seen", 140), ("last_seen", "Last seen", 140),
                       ("files", "Seen in file(s)", 300))

    def init_state(self):
        super().init_state()
        self.local_accounts = {}            # accounts that launched the game (shown below)
        self.local_lower = set()            # lower-cased names, for "likely you" / exclusion
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
        self.exclude_var.trace_add("write", lambda *_: self.schedule_filter())
        ttk.Entry(ef, textvariable=self.exclude_var, width=60).pack(fill="x")
        self.auto_exclude_local = tk.BooleanVar(value=True)
        ttk.Checkbutton(ef, text="Hide the launching account(s) from the players table above",
                        variable=self.auto_exclude_local,
                        command=self.apply_filter).pack(anchor="w", pady=(4, 0))
        self.local_names_label = ttk.Label(ef, text="Launching accounts: none yet (scan first)",
                                           foreground="gray")
        self.local_names_label.pack(anchor="w")

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
        self.local_lower = {n.lower() for n in self.local_accounts}
        self.acct_tree.delete(*self.acct_tree.get_children())
        for values in self._account_rows():
            self.acct_tree.insert("", "end", values=values)
        if self.local_accounts:
            normal_fg = ttk.Style(self).lookup("TLabel", "foreground") or "black"
            self.local_names_label.config(
                text="Launching account(s): " + ", ".join(sorted(self.local_accounts)),
                foreground=normal_fg)
        else:
            self.local_names_label.config(
                text="Launching accounts: none found (no \"Setting user:\" line in these logs)",
                foreground="gray")

    def done_message(self, rows):
        n = len(self.local_accounts)
        msg = f"Found {len(rows)} unique username(s) across the scanned logs. "
        if n > 1:
            return msg + f"{n} different accounts launched the game on this PC - worth a look."
        return msg + f"{plural(n, 'account', 'accounts')} launched the game here."

    # ---- filtering / display ----------------------------------------------
    def _excluded_set(self):
        excluded = {n.strip().lower() for n in self.exclude_var.get().split(",") if n.strip()}
        if self.auto_exclude_local.get():
            excluded |= self.local_lower
        return excluded

    def visible_rows(self):
        f = self.current_filter()
        excluded = self._excluded_set()
        return [r for r in self.rows
                if r["name"].lower() not in excluded and (not f or f in r["name"].lower())]

    def export_rows(self):
        excluded = self._excluded_set()
        return [r for r in self.rows if r["name"].lower() not in excluded]

    def _likely_you(self, r):
        return "yes" if r["name"].lower() in self.local_lower else ""

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
    file_count = 0

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
    """Both panels in one vertically scrollable page."""

    def __init__(self, parent):
        super().__init__(parent, padding=0)
        self.canvas = canvas = tk.Canvas(self, highlightthickness=0)
        vsb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        body = ttk.Frame(canvas, padding=8)
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", self._on_wheel, add="+")

        self.logs = LogsPanel(body)
        self.logs.pack(fill="both", expand=True)

        box = ttk.LabelFrame(body, text="Launcher accounts / profile names", padding=8)
        box.pack(fill="x", pady=(16, 0))
        self.accounts = AccountsPanel(box)
        self.accounts.pack(fill="x")

    def _on_wheel(self, event):
        """Scroll this page only when the pointer is over it - and not over a table,
        text box or list that scrolls itself. (A bare bind_all would scroll this page
        while the user is on any other tab.)"""
        try:
            under = self.winfo_containing(event.x_root, event.y_root)
        except (KeyError, tk.TclError):         # tkinter bug with combobox popups
            return
        if under is None or not str(under).startswith(str(self)):
            return
        if isinstance(under, (ttk.Treeview, tk.Text, tk.Listbox)):
            return
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


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
        ttk.Label(self, text=f"{APP_NAME} {VERSION_LABEL}", font=("Segoe UI", 18, "bold")
                  ).pack(pady=(16, 4))
        ttk.Label(self, text="Credits", font=("Segoe UI", 13, "bold")).pack(pady=(24, 10))
        for name in self.NAMES:
            ttk.Label(self, text=name, font=("Segoe UI", 11)).pack(pady=2)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------
# Palettes follow the Sun Valley (Windows 11) theme so classic tk widgets
# (Text / Listbox / Canvas / sidebar) match the ttk ones.
LIGHT_COLORS = dict(bg="#fafafa", fg="#1a1a1a", field_bg="#ffffff", select="#005fb8",
                    select_fg="#ffffff", high="#c62828", context="#a15c00",
                    border="#d0d0d0", accent="#005fb8", hover="#f0f0f0",
                    active="#e4e4e4", muted="#707070")
DARK_COLORS = dict(bg="#1c1c1c", fg="#f2f2f2", field_bg="#2b2b2b", select="#57c8ff",
                   select_fg="#000000", high="#ff6b6b", context="#e0a030",
                   border="#404040", accent="#57c8ff", hover="#282828",
                   active="#363636", muted="#a0a0a0")

# (tab title, tab class) in display order - add a new tab by adding a line here.
TABS = [
    ("Memory Scan", MemoryScanTab),
    ("DLL Scanner", DLLScannerTab),
    ("Log Checker", LogCheckerTab),
    ("Mods Scanner", ModsScannerTab),
    ("Versions Audit", VersionsAuditTab),
    ("Servers", ServersTab),
    ("Recycle Bin", RecycleBinTab),
    ("Prefetch", PrefetchTab),
    ("Crash Reports", CrashReportsTab),
    ("Installed Programs", InstalledProgramsTab),
    ("Hosts Check", HostsCheckTab),
    ("Process Timeline", ProcessTimelineTab),
    ("Credits", CreditsTab),
]
PINNED_BOTTOM = {"Credits"}      # these sidebar entries sit at the bottom


class SidebarItem(tk.Frame):
    """One clickable sidebar entry: accent bar + label, with hover/selected states."""

    def __init__(self, parent, text, command):
        super().__init__(parent, cursor="hand2")
        self.selected = False
        self.hovered = False
        self.colors = LIGHT_COLORS
        self.bar = tk.Frame(self, width=3)
        self.bar.pack(side="left", fill="y", pady=6)
        self.label = tk.Label(self, text=text, anchor="w", font=("Segoe UI", 10),
                              padx=12, pady=7)
        self.label.pack(side="left", fill="x", expand=True)
        for w in (self, self.bar, self.label):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>", lambda e: self._set_hover())
            w.bind("<Leave>", lambda e: self.after_idle(self._set_hover))

    def _set_hover(self):
        try:
            under = self.winfo_containing(*self.winfo_pointerxy())
        except (KeyError, tk.TclError):
            return
        hovered = under is not None and (under is self or str(under).startswith(str(self) + "."))
        if hovered != self.hovered:
            self.hovered = hovered
            self.apply(self.colors)

    def set_selected(self, selected):
        self.selected = selected
        self.apply(self.colors)

    def apply(self, c):
        self.colors = c
        bg = c["active"] if self.selected else (c["hover"] if self.hovered else c["bg"])
        self.configure(bg=bg)
        self.label.configure(bg=bg, fg=c["fg"])
        self.bar.configure(bg=c["accent"] if self.selected else bg)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION_LABEL}")
        self.geometry("1200x780")
        self.minsize(1000, 640)

        self.style = ttk.Style(self)
        self.dark_mode = tk.BooleanVar(value=False)
        self.colors = LIGHT_COLORS
        self.current = None
        self.items = {}      # title -> SidebarItem
        self.tabs = {}       # title -> tab widget

        self._build_sidebar()
        ttk.Separator(self, orient="vertical").pack(side="left", fill="y")
        self._build_main()

        self.show_tab(TABS[0][0])
        self._apply_theme(LIGHT_COLORS)

        self.bind("<Control-Next>", lambda e: self._step_tab(1))
        self.bind("<Control-Prior>", lambda e: self._step_tab(-1))

        if psutil is None:
            messagebox.showwarning(
                "psutil unavailable",
                "psutil could not be installed automatically. The Memory Scan and "
                "Recycle Bin tabs still work; Process Timeline needs psutil - "
                "install manually with: pip install psutil")

    # ---- layout -----------------------------------------------------------
    def _build_sidebar(self):
        side = ttk.Frame(self, width=220)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        ttk.Label(side, text="Scarf's SS Tool", font=("Segoe UI Semibold", 14)
                  ).pack(anchor="w", padx=16, pady=(18, 0))
        ttk.Label(side, text=f"Screenshare helper  -  v{VERSION_LABEL}", foreground="gray"
                  ).pack(anchor="w", padx=16, pady=(0, 14))

        # Bottom first (pack stacks bottom-up): dark-mode switch, then pinned tabs.
        switch_style = "Switch.TCheckbutton" if sv_ttk else "TCheckbutton"
        ttk.Checkbutton(side, text="Dark mode", style=switch_style,
                        variable=self.dark_mode, command=self.toggle_dark_mode
                        ).pack(side="bottom", anchor="w", padx=16, pady=(8, 16))
        for title, _ in reversed(TABS):
            if title in PINNED_BOTTOM:
                self._add_item(side, title, "bottom")
        for title, _ in TABS:
            if title not in PINNED_BOTTOM:
                self._add_item(side, title, "top")

    def _add_item(self, parent, title, where):
        item = SidebarItem(parent, title, lambda t=title: self.show_tab(t))
        item.pack(side=where, fill="x", padx=(8, 8), pady=1)
        self.items[title] = item

    def _build_main(self):
        main = ttk.Frame(self)
        main.pack(side="left", fill="both", expand=True)

        self.page_title = tk.StringVar()
        ttk.Label(main, textvariable=self.page_title, font=("Segoe UI Semibold", 18)
                  ).pack(anchor="w", padx=20, pady=(16, 4))

        footer = ttk.Label(
            main,
            text=("For use during a screenshare the other person has agreed to. "
                  "Results are leads to review, not proof of cheating."),
            foreground="gray", anchor="w", justify="left")
        footer.pack(side="bottom", fill="x", padx=20, pady=(4, 10))
        footer.bind("<Configure>", lambda e: footer.configure(wraplength=max(200, e.width)))

        content = ttk.Frame(main)
        content.pack(fill="both", expand=True, padx=8)
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)
        for title, tab_class in TABS:
            tab = tab_class(content)
            tab.grid(row=0, column=0, sticky="nsew")
            tab.grid_remove()                      # only the selected page is mapped
            self.tabs[title] = tab

    # ---- navigation -------------------------------------------------------
    def show_tab(self, title):
        if title == self.current:
            return
        if self.current:
            self.tabs[self.current].grid_remove()
            self.items[self.current].set_selected(False)
        self.tabs[title].grid()
        self.items[title].set_selected(True)
        self.page_title.set(title)
        self.current = title

    def _step_tab(self, delta):
        titles = [t for t, _ in TABS]
        self.show_tab(titles[(titles.index(self.current) + delta) % len(titles)])

    # ---- theming ----------------------------------------------------------
    def toggle_dark_mode(self):
        self._apply_theme(DARK_COLORS if self.dark_mode.get() else LIGHT_COLORS)

    def _apply_theme(self, c):
        self.colors = c
        dark = c is DARK_COLORS
        if sv_ttk:
            sv_ttk.set_theme("dark" if dark else "light")
        else:
            self._apply_fallback_theme(c)
        self.configure(bg=c["bg"])
        self._recolor_classic_widgets(self, c)
        for item in self.items.values():
            item.apply(c)
        self._set_titlebar_dark(dark)

    def _set_titlebar_dark(self, dark):
        """Match the Windows title bar to the theme (Win10 1809+ / Win11)."""
        try:
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1 if dark else 0)
            for attr in (20, 19):       # DWMWA_USE_IMMERSIVE_DARK_MODE (new / old id)
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                    break
        except Exception:
            pass

    def _apply_fallback_theme(self, c):
        """Used only when sv-ttk could not be installed: plain 'clam' with our colors."""
        s = self.style
        s.theme_use("clam")
        s.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field_bg"])
        for name in ("TFrame", "TLabel", "TLabelframe", "TLabelframe.Label", "TCheckbutton"):
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
        s.configure("Treeview", background=c["field_bg"], fieldbackground=c["field_bg"],
                    foreground=c["fg"])
        s.configure("Treeview.Heading", background=c["bg"], foreground=c["fg"])
        s.map("Treeview", background=[("selected", c["select"])],
              foreground=[("selected", c["select_fg"])])
        s.configure("Horizontal.TProgressbar", background=c["select"])

    def _recolor_classic_widgets(self, widget, c):
        """ttk styles don't cover classic tk widgets (Text/Listbox/Canvas), so walk the
        whole widget tree and recolor those by hand. New tabs get this for free."""
        for child in widget.winfo_children():
            try:
                if isinstance(child, (tk.Text, tk.Listbox)):
                    opts = dict(bg=c["field_bg"], fg=c["fg"], relief="flat", borderwidth=0,
                                highlightthickness=1, highlightbackground=c["border"],
                                highlightcolor=c["accent"],
                                selectbackground=c["select"], selectforeground=c["select_fg"])
                    if isinstance(child, tk.Text):       # Listbox has no insertbackground option
                        opts["insertbackground"] = c["fg"]
                    child.configure(**opts)
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
