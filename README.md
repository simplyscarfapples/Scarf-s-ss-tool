# Scarf's SS Tool (Future plans)

A Windows GUI for checking a PC for cheat clients during a screenshare the
other person has agreed to. Everything is visible and on-demand: it reads
files, registry entries and process info that already exist, and never
captures keystrokes or runs in the background. Results are leads to review,
not proof of cheating.

## Future plans
Currently this branch stands as a road map for any features we would like to add to version 3 and beyond. 

## Features that may release with 3.0
- Adding an easier way to scan such as having options like "Light scan" which would do a memory and jar scan in conjunction
- A more custom gui possibility based off of MacOS Tahoe

## Requirements
- Windows
- Python 3.8+ (64-bit, to read 64-bit Minecraft's memory)
- Admin rights are recommended (needed for Prefetch, the system-wide Windows
  Error Reporting folder, and some process memory/module access). Every tab
  that benefits has a "Run as admin" button.
- Python packages (see `requirements.txt`): `psutil` and `sv-ttk`

## Run
```
python Scarf_SS_tool.py
```
Missing dependencies (`psutil`, `sv-ttk`) install automatically on first run.
To install them yourself instead:
```
pip install -r requirements.txt
```
If `sv-ttk` can't be installed, the tool still runs using a plain fallback
theme. If `psutil` is missing, only the Process Timeline tab is affected.

## Interface
- Tabs are listed in a **sidebar** on the left; click one to open it.
  `Ctrl+PageUp` / `Ctrl+PageDown` switch between them.
- The **Dark mode** switch and **Credits** are at the bottom of the sidebar.
- Styled with the Sun Valley (Windows 11) theme via `sv-ttk`.

## Keywords
One keyword list drives the Memory Scan, Mods Scanner, Jar Inspector, Versions
Audit and Crash Reports tabs. Edit it in the Memory Scan tab (it can be loaded
from and saved to a text file) and the others pick it up.

- **Red** = a distinctive cheat/client name that rarely shows up by accident.
- **Amber** = a common word that also appears in innocent software
  (start a keyword line with `?` to make it amber).

Matching in the file-based tabs ignores case, spaces, `_` and `-`, so
`kill aura` also finds a class called `KillAura`. The Mods Scanner also takes
extra keywords for a single scan without changing the shared list.

## Signature database
`signatures.json` (next to the script) holds known-cheat knowledge that
keywords can't catch:

- **hashes**: exact SHA-256 values of confirmed cheat files
- **jar_patterns**: text that appears in entry paths inside a cheat jar
  (minimum 6 characters)

Each entry has a name and a severity (`high` = red, `context` = amber). The
Mods Scanner, Jar Inspector and DLL Scanner check against it, and a match is
shown as `HIGH: signature <name>`. Edit the file by hand ("Open file" creates
it if missing, "Reload" re-reads it) or add confirmed files from the Mods
Scanner or Jar Inspector. Only add files you are sure about: a wrong entry will
flag innocent players later.

A hash only matches an exact, unmodified copy, so a rebuilt cheat will not
match. Treat a miss as "unknown", not "clean". If you run a one-file `.exe`,
keep in mind its script folder is temporary, so edits to the signature
database made from it will not persist; use the `.py` or a one-dir build.

## Features
- **Memory Scan**: scans a running process's memory for keyword matches, with
  optional scanning of all matching processes. Keyword-only scans use a fast
  path; "save all strings" is optional. Each run writes a log to a `logs`
  folder next to the script. If a process can't be opened or read, the scan is
  reported as failed rather than as "0 matches".
- **DLL Scanner**: lists DLLs loaded into a process and marks each as system,
  game folder or other. Modules outside the Windows folder are hashed and
  checked against the signature database.
- **Log Checker**:
  - lists every account that *launched the game* on this PC (from
    `Setting user:` lines, with launch counts and first/last seen; several
    names = likely alts)
  - lists other players seen in chat/join/leave messages (a weaker signal;
    the launching accounts are hidden from this list by default)
  - lists player names from launcher account files (never tokens, passwords
    or e-mail addresses)
- **Mods Scanner**: finds mods folders (including per-profile ones like
  CurseForge, Modrinth, Dawn, and `mods\<version>` subfolders) and, optionally,
  installed game versions. Opens each jar and checks class/package names, file
  name and declared mod name against the keyword list (catches renamed
  cheats) and its entry paths and hash against the signature database. Shows
  the declared name next to the file name and hashes jars. Jars are processed
  in parallel.
- **Jar Inspector**: inspects one file: SHA-256, last-modified date, whether
  it is already in the signature database, and what the keyword list and
  signatures make of it. Can copy the hash or add the file to `signatures.json`
  as a confirmed cheat.
- **Versions Audit**: audits each `versions\<name>\` folder and launcher
  profile. Compares the jar with the official SHA-1/size recorded in its own
  version json (a mismatch shows as DIFFERS), and flags json ids that don't
  match the folder, missing jars, unfamiliar main classes, and JVM options such
  as `-javaagent` or `-Xbootclasspath`.
- **Servers**: lists saved servers from `servers.dat` across launchers and
  profiles.
- **Recycle Bin**: shows deleted-file history from `$Recycle.Bin` on every
  drive.
- **Prefetch**: shows program run history. Reads Windows 10/11 compressed
  prefetch files in full: last run, run count and the 8 most recent runs.
- **Crash Reports**: reads Minecraft crash reports, JVM `hs_err` logs and
  Windows Error Reporting entries for Java. Checks them against the keyword
  list, lists DLLs loaded from outside Windows / Program Files / Java folders,
  and flags suspicious JVM options.
- **Installed Programs**: lists installed software from the registry,
  including leftover entries from uninstalled programs.
- **Hosts Check**: shows active entries in the Windows hosts file that block
  or redirect domains.
- **Process Timeline**: lists what started after a chosen process or time,
  with optional auto-refresh.
- Filtering, sortable columns and CSV export on the table tabs. Exported text
  is sanitized so it can't run as a spreadsheet formula.
- Session tokens in launch lines, crash reports and memory strings are
  redacted; they are never displayed, logged or exported.
- Light and dark mode

## Notes
- A flag is a reason to look closer, not a verdict. Amber flags in particular
  are often innocent (build tools, resource packs, legitimate agents).
- The official-hash check in Versions Audit relies on a json file the user
  could also have edited, so treat it as a lead.
- Signature matches are exact-file matches; no match does not mean clean.
- The dark title bar needs Windows 10 1809 or newer.

## Credits
Scarf, Zelz, Clickbait, that random guy that told me about the log idea,
the dead ghost of kizzer
