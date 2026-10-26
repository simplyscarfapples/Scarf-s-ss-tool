# Security Policy

Scarf's SS Tool runs on someone else's PC, often with admin rights, and reads sensitive things like process memory, logs and launcher files. Because of that, security and privacy problems matter more here than in a typical hobby project. Thank you for helping keep it safe.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release (`main`) | Yes |
| 2.0 Beta | Yes (fixes land here first) |
| Older releases | No. Please update. |

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

1. Go to the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting).
2. If that isn't available, contact the maintainer directly through the contact method listed on the GitHub profile, and ask for a private channel before sending details.

Include as much of this as you can:

- What the problem is and which tab or function it affects.
- Steps to reproduce, or a small proof of concept.
- The impact: what an attacker could do or learn.
- Your Windows version, Python version (or exe build) and whether it ran as admin.
- Any suggested fix.

Please **don't include real personal data** (usernames, UUIDs, IP addresses, tokens) in a report. Use fake or redacted values.

### What to expect

These are targets, not guarantees, since this is a volunteer project:

- Acknowledgement within about 7 days.
- An initial assessment within about 14 days.
- A fix or mitigation as soon as it's practical, with credit in the release notes if you'd like it.

Please give us reasonable time to ship a fix before you disclose publicly. If a report is declined, we'll explain why.

## What's in scope

- **Leaking secrets.** Session or access tokens, account details or other private data appearing in the UI, CSV exports or saved log files when they shouldn't.
- **Code execution or unsafe handling of scanned data.** Files, jars, NBT files, logs, crash reports or Prefetch files crafted to crash the tool, run code, write outside intended folders, exhaust memory (for example zip bombs), or trick the tool into hiding or faking results.
- **Export problems.** CSV or log output that can run formulas or commands when opened (formula injection).
- **Privilege issues.** Problems with the "Run as admin" relaunch or with files the tool creates, such as predictable paths or unsafe permissions.
- **Supply chain.** Issues with dependencies, the automatic first-run `pip install`, release files or build scripts that could lead to tampered code reaching users.
- **Anything that breaks the project's ground rules:** the tool must be read-only, visible and on-demand, and must not make network calls for scanning (see `CONTRIBUTING.md`).

## Detection bypasses

Cheat developers read public issues too. If you've found a way to **evade detection** (for example, a trick that hides a client from a scanner), please report it privately using the same process above rather than publishing the technique. These are handled as normal bugs once a fix is ready, but we'd like the fix to ship before the details are public.

Ordinary **false positives** and missing keywords are not security issues. Report those as regular issues.

## Out of scope

- Findings that need the attacker to already have full control of the machine and don't cross a boundary the tool is meant to protect. A user who controls the PC can always tamper with what the tool sees, which is why results are treated as leads, not proof.
- Reports about third-party software (Python, Windows, `psutil`, `sv-ttk`) unless this project uses them unsafely. Please report those upstream.
- Social engineering, spam, or denial of service against the maintainers or GitHub itself.

## Safe harbour

If you act in good faith, stay within this policy, avoid harming other people's data or systems, and give us time to respond, we won't pursue or support legal action against you for your research. Test only on machines and accounts you own or have permission to use.

## Staying safe as a user

- **Download only from the official repository** or its official releases. Don't run copies from Discord, forums or file hosts, which may have been modified.
- If checksums are published with a release, compare them before running.
- **The tool is meant to be offline.** It shouldn't send your data anywhere. Its only network use is the one-time dependency install on first run. If you see unexpected network activity, report it.
- **Only run it with the other person's agreement,** and tell them what it reads. Scan results and logs can contain private information.
- **Local files:** Memory Scan can save logs and dumps next to the tool (in a `logs` folder), and CSV exports contain whatever the scan found. Treat them as sensitive, share them only with people who need them, and delete them when you're done.
- Run as admin only when you need to (Prefetch, system-wide error reports, some process access). The tool works with reduced results without it.

## Credit

Thanks to everyone who reports issues responsibly. With your permission, we'll credit you in the release notes.
