# Scarf's SS Tool

A Windows GUI for checking a PC for cheat clients during a screenshare the
other person has agreed to. Everything is visible and on-demand: it reads
files, registry entries and process info that already exist, and never
captures keystrokes or runs in the background. Results are leads to review,
not proof of cheating.

## Requirements
- Windows
- Python 3.8+ (64-bit, to read 64-bit Minecraft's memory)
- Admin rights are recommended (needed for Prefetch, the system-wide Windows
  Error Reporting folder, and some process memory/module access). Every tab
  that benefits has a "Run as admin" button.

## Run
```
python Scarf_SS_tool.py
```
Missing dependencies (`psutil`) install automatically on first run.

## Keywords
One keyword list drives the Memory Scan, Mods Scanner, Versions Audit and
Crash Reports tabs. Edit it in the Memory Scan tab and the others pick it up.

- **Red** = a distinctive cheat/client name that rarely shows up by accident.
- **Amber** = a common word that also appears in innocent software
  (start a keyword line with `?` to make it amber).

Matching in the file-based tabs ignores case, spaces, `_` and `-`, so
`kill aura` also finds a class called `KillAura`.

## Features
- **Memory Scan**: scans a running process's memory for keyword matches.
  Keyword-only scans use a fast path; "save all strings" is optional. Each run
  writes a log to a `logs` folder next to the script.
- **DLL Scanner**: lists DLLs loaded into a process and marks each as system,
  game folder or other.
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
  cheats), shows the declared name next to the file name, and hashes jars.
  Jars are processed in parallel.
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
  and flags suspicious JVM options. Session tokens are never displayed or
  exported.
- **Installed Programs**: lists installed software from the registry,
  including leftover entries from uninstalled programs.
- **Hosts Check**: shows active entries in the Windows hosts file that block
  or redirect domains.
- **Process Timeline**: lists what started after a chosen process or time,
  with optional auto-refresh.
- Filtering, sortable columns and CSV export on the table tabs
- Dark mode

## Notes
- A flag is a reason to look closer, not a verdict. Amber flags in particular
  are often innocent (build tools, resource packs, legitimate agents).
- The official-hash check in Versions Audit relies on a json file the user
  could also have edited, so treat it as a lead.

## Credits
Scarf, Zelz, Clickbait, that random guy that told me about the log idea,
the dead ghost of kizzer