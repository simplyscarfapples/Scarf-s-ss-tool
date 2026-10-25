# Contributing to Scarf's SS Tool

Thanks for wanting to help. This is a small Windows tool used during Minecraft screenshares, so the most valuable contributions are **accurate detections, fewer false positives, and fixes that keep the tool safe to run on someone else's PC.**

## Ground rules (read these first)

These come before any code rules because they define what the project is.

1. **Consent-based and visible.** The tool is for screenshares the other person has agreed to. Everything it does must be on-demand and visible in the UI. No hidden behaviour, no background services, no persistence, no auto-start.
2. **Read-only.** Scanners may read files, memory, the registry and process info. They must **not** delete, modify, kill, inject into, or upload anything on the inspected machine.
3. **No network calls** for scanning or reporting. The only network use is the one-time dependency install described in the README.
4. **Results are leads, not verdicts.** Wording in the UI, flags and docs must never claim proof of cheating. Keep the "review, not proof" framing.
5. **Never show or save secrets.** Session tokens, access tokens and similar values must not appear in the UI, CSV exports or log files. Anything that displays text taken from the inspected machine (memory strings, command lines, logs, crash reports) must pass through `redact_secrets()`. If you find a case it misses, extend the redaction rather than working around it.

Contributions that break these rules will be declined, however useful they are otherwise.

## Ways to contribute

- **Report a bug** or a false positive (see below).
- **Suggest or add keywords** for new cheat clients.
- **Improve a scanner** (more launchers, more log formats, better parsing).
- **Fix UI issues**, especially high-DPI, older Windows 10 builds and dark/light mode problems.
- **Improve docs** and the README.

For anything larger than a small fix, please open an issue first so we can agree on the approach before you spend time on it.

## Reporting bugs and false positives

Open an issue and include:

- Windows version, Python version (or the exe build), and whether the tool was run as admin.
- Which tab, and the exact steps to reproduce.
- What you expected vs. what happened. For crashes, paste the traceback.
- For a **false positive**: the flagged keyword/row and why it's legitimate (for example, a build tool or resource pack).

**Please remove personal data before posting.** Blur or delete usernames, UUIDs, IP addresses and anything resembling a token in screenshots, logs and CSV exports. Don't post a real person's scan results to accuse or shame them.

## Development setup

```
git clone https://github.com/simplyscarfapples/Scarf-s-ss-tool.git
cd Scarf-s-ss-tool
pip install -r requirements.txt
python "Scarf SS tool.py"
```

The tool is Windows-only and uses `tkinter`, `psutil` and `sv-ttk`. It still runs without `sv-ttk` (plain fallback theme), so please keep that fallback working.

## Code layout

The single script is organised in two halves:

- **Backend scanners first** (memory, prefetch, jars, versions, crash reports, logs, hosts, installed programs, recycle bin, servers.dat, and so on). These are plain functions with no GUI code, so they stay easy to test and reuse.
- **GUI second.** Every table tab is built on the `TableTab` / `ScanTab` base classes. See the "GUI" section in the source for how a tab is wired up.

### Adding a new tab

1. Write the scanner as a backend function that returns rows (dicts) and accepts a `stop` event where it can run long.
2. Subclass `ScanTab` (or `TableTab`) and define its columns, searchable fields, row values and detail text.
3. Add one `("Tab title", TabClass)` line to the `TABS` list. The sidebar, theming and keyboard navigation pick it up automatically.
4. Add a short entry to the README tab list.

## Code guidelines

- **Keep the UI responsive.** Long scans run in a worker thread. Don't touch Tk widgets from a worker thread; send results to the main thread through a queue and poll it (as the Memory Scan tab does).
- **Workers must always finish.** Wrap worker bodies in `try/except/finally` so the UI always receives a "done" message, even if setup (like creating a log folder) fails. Make sure queue-polling loops reschedule themselves in a `finally`.
- **Support cancelling.** Pass the `stop` event into loops over files, jars or regions, and check it.
- **Handle errors per item.** One unreadable file, locked jar or access-denied process must not abort the whole scan. Skip it and carry on.
- **Be careful with exports.** CSV cells can contain text from the inspected machine, so guard against spreadsheet formula injection (cells starting with `=`, `+`, `-`, `@`), and show an error if the file can't be written.
- **Don't hardcode paths** like `C:\Windows`. Use environment variables (`%WINDIR%`, `%APPDATA%`, `%LOCALAPPDATA%`).
- **Keep dependencies minimal.** Don't add a package without discussing it first. If a new one is approved, pin its version in `requirements.txt`.
- **Style:** follow the existing style (type-light, short docstrings on public functions, comments that explain *why*). Keep functions small enough to read.

## Adding or changing keywords

The keyword list drives Memory Scan, Mods Scanner, Versions Audit, Crash Reports and Logs.

- Matching in file-based tabs ignores case, spaces, `_` and `-`, so `kill aura` and `KillAura` are the same keyword. Don't add both.
- Use the **high** tier only for names that are very unlikely to be innocent. Use the **context** tier (amber) for terms that have legitimate uses.
- Before adding a short or common word, check it doesn't match ordinary files. Substring matching means a short keyword can hit unrelated names (for example, `nofall` matches `NoFallback`). If a keyword is noisy, make it more specific or put it in the context tier.
- In your PR, say where the keyword comes from (client name, release, or sample) and how you checked for false positives.

## Testing

There's no automated test suite yet, so please test by hand and say what you did in your PR:

- `python -m py_compile "Scarf SS tool.py"` passes.
- The app starts, and the tab you changed works in **light and dark mode**.
- Test **with and without admin rights**, and with `sv-ttk` and `psutil` missing if your change touches the theme or process code.
- For scanner changes, test against realistic data: a real `.minecraft` folder, several launchers if you touched path discovery, a crash report or `hs_err` file for crash parsing.
- If you add a test or sample-data fixture, make sure it contains no real usernames, tokens or personal paths.

## Pull requests

- Branch from the latest `main` (or the branch maintainers point you to for a release in progress) and keep each PR focused on one change.
- Write a clear title and describe **what** changed, **why**, and **how you tested it**. Include before/after screenshots for UI changes.
- Keep unrelated refactors and formatting churn out of the PR.
- Update the README if you change behaviour, tabs or requirements.
- Be ready for review feedback. Small, readable PRs get merged faster.

## Security issues

If you find a vulnerability (for example, a way for scanned data to run code, or a leak of secrets), **don't open a public issue.** Use GitHub's private vulnerability reporting on the repository's Security tab, or contact the maintainer directly.

## Conduct

Be respectful and constructive. Assume good faith, critique code rather than people, and remember that screenshares involve real people who may be nervous or falsely accused. Harassment, doxxing, and using the project to target individuals are not welcome.

## License

By contributing, you agree that your contributions are licensed under the same license as the project.
