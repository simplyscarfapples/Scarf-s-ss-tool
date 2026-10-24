# Scarf's SS Tool 1.0

A Windows GUI for checking a PC for cheat clients during a screenshare the
other person has agreed to. Results are leads to review, not proof of cheating.

## Requirements
- Windows
- Python 3

## Run
```
python mc_string_logger_gui.py
```
Missing dependencies (`psutil`) install automatically on first run.

## Features
- **Memory Scan** — scans a running process's memory for keyword matches (cheat/client names)
- **DLL Scanner** — lists DLLs loaded into a process, flags ones outside system/game folders
- **Log Checker** — scans log files for usernames, listed as possible alts
- **Launcher Accounts** — lists profile names from launcher account files (no tokens/passwords)
- **Mods Scanner** — finds mods folders (including per-profile ones like CurseForge/Modrinth/Dawn) and hashes jars
- **Servers** — lists saved servers from servers.dat across launchers/profiles
- **Recycle Bin** — shows deleted-file history
- **Prefetch** — shows program run history
- **Installed Programs** — lists installed software from the registry, including leftover entries from uninstalled programs
- **Hosts Check** — shows active entries in the Windows hosts file that block or redirect domains
- **Process Timeline** — lists what launched after a chosen process
- Dark mode
- Auto-installs missing dependencies

## Credits
Scarf, Zelz, Clickbait, that random guy that told me about the log idea,
the dead ghost of kizzer