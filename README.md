# Scarf's SS Tool

A Windows GUI for checking a PC for cheat clients during a screenshare the
other person has agreed to. Results are leads to review, not proof of cheating.

## Requirements
- Windows
- Python 3.8+ (64-bit, to read 64-bit Minecraft's memory)

## Run
```
python Scarf_SS_tool.py
```
Missing dependencies (`psutil`) install automatically on first run.

## Features
- **Memory Scan** — scans a running process's memory for keyword matches (cheat/client names). Keywords have two levels: red = distinctive cheat name, amber = common word that also shows up in innocent software (start a keyword line with `?` to make it amber)
- **DLL Scanner** — lists DLLs loaded into a process, flags ones outside system/game folders
- **Log Checker** — lists every account that *launched the game* on this PC (from `Setting user:` lines, with launch counts and first/last seen; several names = likely alts), plus a weaker list of other players seen in chat/join/leave messages
- **Launcher Accounts** — lists player names from launcher account files (no tokens, passwords or e-mail addresses)
- **Mods Scanner** — finds mods folders (including per-profile ones like CurseForge/Modrinth/Dawn, and `mods\<version>` subfolders) and the installed game versions; opens each jar and checks class/package names, file name and declared mod name against the keyword list (catches renamed cheats), shows the declared name next to the file name, and hashes jars
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
