# OpenSecurity

An on-demand malware scanner for Windows, built from scratch in C#/.NET.

By **Nolan Crowley**. Open source under the [MIT License](LICENSE).

## Disclaimer

**Nolan Crowley is not responsible for:**
- Malware infections, data loss, or any other damage to your computer, files, or accounts, whether or not OpenSecurity was installed or running at the time
- Any misuse of this software, including use for any purpose other than scanning your own systems with authorization

Use it at your own risk, keep independent backups of anything important, and don't rely on it as your only line of defense.

## What it does

OpenSecurity scans a file, folder, archive, or entire drive using several detection layers:

- **Hash signatures** — SHA-256 exact match against a known-bad hash list (`signatures/hashes.txt`)
- **Fuzzy hashing** — a self-contained context-triggered piecewise hashing (CTPH) implementation, the technique behind ssdeep (`signatures/fuzzy_hashes.txt`). Unlike SHA-256, a recompiled build or repacked installer that shares most of its content with a known-bad sample still scores a high similarity match, so near-duplicate variants get caught even when no exact hash matches
- **Pattern rules** — simplified YARA-style string/hex matching (`rules/*.yar`) — 10 built-in rules covering EICAR, PowerShell/AMSI abuse, webshells, script downloaders, living-off-the-land binary abuse, ransom-note language, and Office macro auto-exec patterns
- **PE heuristics** — a from-scratch PE (Portable Executable) header parser that scores packing signs (high-entropy sections, known packer section names like UPX/ASPack/Themida), RWX sections, overlay data (bytes appended past the last section), suspicious API imports (process injection, anti-debugging, credential access, network/exfiltration — and combinations like network + injection APIs together, a common backdoor pattern)
- **Mach-O heuristics** — a from-scratch macOS Mach-O header parser (thin and fat/universal binaries) scoring the same structural traits where they have a macOS equivalent: RWX segments, high-entropy segments, missing code signature, and dylibs linked from unusual locations (`/tmp`, `Downloads`, path traversal) rather than the standard system/bundle-relative paths
- **Authenticode validation** — not just "is it signed", but whether the signature actually chains to a trusted root certificate; a self-signed or tampered signature is scored differently than a properly CA-signed one
- **Archive scanning** — `.zip` and `.7z` files are opened and every entry inside is scanned with the same pipeline, including password-protected archives (tried against a configurable list of conventional passwords in `signatures/archive_passwords.txt` — malware sample collections are routinely shared encrypted, to stop AV engines auto-deleting them and prevent accidental double-click execution) and archives nested inside archives (up to 5 levels deep — a zip inside a zip is common when a collection repackages a third-party installer), with zip-bomb guards (per-entry and total decompressed size caps, entry count cap, recursion depth cap)

No external antivirus/YARA native dependencies — everything is self-contained managed code. Directory scans run across all CPU cores in parallel while still streaming results back live as each file finishes.

Beyond detection, it also has:

- **Quarantine** — move a detected file into an isolated, obfuscated holding area instead of just reporting it, with restore/delete
- **Signature updates** — pull a plaintext SHA-256 hash feed (e.g. [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/export/txt/sha256/full/)) from any URL and merge new entries into the local hash database
- **Allowlist** — mark a file as trusted by hash to suppress pattern-rule/heuristic false positives on it in future scans (a hash-signature match always still wins, so this can't hide a confirmed-malicious file)
- **Full-drive scanning** — point it at an entire drive; a resilient directory walker skips inaccessible/protected folders instead of aborting the whole scan
- **Scan history** — every scan is logged locally so you can look back at what was found and when
- **Exportable reports** — save a completed scan's results as JSON or CSV
- **Scheduled scanning** — set up a recurring scan via Windows Task Scheduler, no need to keep the app running
- **Real-time protection** — on by default (a fresh install is protected without touching any settings), a user-mode folder watcher scans new/changed files as they land in chosen folders (Downloads, Desktop, temp by default). A Malicious-verdict detection is auto-quarantined immediately rather than just logged, closing most of the gap between "file lands on disk" and "user double-clicks it" - the closest a user-mode watcher (not a kernel-mode driver, no admin rights or signed driver needed) can get to SmartScreen-style blocking. Reversible any time from the Quarantine tab. The CLI has the same thing: `OpenSecurity.Cli.exe watch [folder...] --quarantine`
- **System tray** — runs quietly in the tray by default, launching automatically at Windows login (a standard per-user Run-key registration, not a system service - no admin rights needed, but it starts at your login, not at raw system boot before anyone signs in) so real-time protection is actually always on. Both this and real-time protection can be turned off from Settings if you'd rather run scans on demand
- **Explorer integration** — an optional "Scan with OpenSecurity" right-click entry for files, folders, and drives, which opens the app and scans immediately
- **Code signing** — release exes are signed (see [Code signing](#code-signing) below for what that does and doesn't get you)

## Projects

- `src/OpenSecurity.Core` — the scan engine and all supporting services (hashing, rules, PE parsing, heuristics, quarantine, history, scheduling, real-time protection, signature updates, reporting)
- `src/OpenSecurity.Cli` — command-line scanner
- `src/OpenSecurity.Ui` — WPF desktop app (dark theme, drag-and-drop, live results, tray icon, Explorer integration)
- `tests/OpenSecurity.Core.Tests` — unit and integration tests for the engine
- `tests/OpenSecurity.Ui.Tests` — tests for Windows-shell integrations (registry-backed context menu)

## Running it

Requires the [.NET SDK](https://dotnet.microsoft.com/download) (net10.0).

```bash
# Desktop app
dotnet run --project src/OpenSecurity.Ui/OpenSecurity.Ui.csproj

# CLI
dotnet run --project src/OpenSecurity.Cli/OpenSecurity.Cli.csproj -- <path> --recursive --verbose
```

Or grab the prebuilt `.exe` from the [Releases](../../releases) page — self-contained, no .NET install required.

## Extending detection

Drop more SHA-256 hashes into `signatures/hashes.txt`, more CTPH fuzzy hashes into `signatures/fuzzy_hashes.txt` (one `blocksize:hash1:hash2  label` per line, same format as the exact-hash list — compute one from a file with `OpenSecurity.Core.Hashing.FuzzyHash.Compute`), or more `.yar` rule files into `rules/` — all load at runtime, no rebuild needed. Add a file's hash to `signatures/allowlist.txt` to stop it being flagged. Add more conventional archive passwords to `signatures/archive_passwords.txt` if you work with a sample source that uses one not already listed.

To pull in more signatures from a feed:

```bash
OpenSecurity.Cli.exe update-signatures https://bazaar.abuse.ch/export/txt/sha256/full/
```

### Validated against a real malware sample set

`signatures/hashes.txt` includes 6,249 hashes of confirmed-malicious samples computed directly from three public, password-protected malware sample collections:

- [Endermanch/MalwareDatabase](https://github.com/Endermanch/MalwareDatabase) (2,741 hashes — mostly rogue/PUP, joke, trojan, and ransomware samples)
- [Pyran1/MalwareDatabase](https://github.com/Pyran1/MalwareDatabase) (1,637 hashes — 200+ categories spanning Windows, Linux, Android, and cross-platform malware)
- A macOS-specific malware collection (1,870 hashes — Mach-O binaries, .app bundles, .dmg/.pkg installers)

`signatures/fuzzy_hashes.txt` includes 3,276 CTPH fuzzy hashes computed from a representative sample (~300 archives) drawn from all three collections above, proportional to their size. Validated end-to-end against a real sample: a modified copy of a real ZeuS variant from the Pyran1 collection (25% of its bytes changed, producing a completely different SHA-256 that the exact-hash list doesn't contain) still scored an 86% fuzzy match and was correctly flagged Suspicious.

Getting these archives open at all is what proved out the password-protected-archive support (all three collections are shared encrypted, each with its own conventional password) and, in this release, surfaced a real gap: some curated archives repackage third-party installers that keep their own original password instead of the collection's convention, so a single zip can mix passwords per entry. The scanner now retries an individual entry against every configured password before giving up on it, instead of assuming one password unlocks the whole archive.

Full combined-dataset scan results (2,116 files, all three collections): **2,092 correctly flagged malicious**, 21 correctly identified as clean (the collections' own non-malware readme/license/script content, not samples), 0 false negatives among files the engine could open. The 3 remaining "error" results are honestly-reported gaps, not misses: one rare zip variant (AES encryption + LZMA compression instead of the near-universal AES+DEFLATE) that the underlying archive library can't decode yet, and two samples split across multi-volume `.zip.001`/`.zip.002` archives (live multi-volume scanning wasn't worth adding for 2 files out of 2,116 — their content was hashed manually instead, so they're still detected once extracted).

## CLI reference

```bash
OpenSecurity.Cli.exe <path> [--recursive] [--verbose] [--quarantine] [--export report.json]
OpenSecurity.Cli.exe list-quarantine
OpenSecurity.Cli.exe restore-quarantine <id>
OpenSecurity.Cli.exe list-history
OpenSecurity.Cli.exe schedule enable <path> [--frequency daily|weekly] [--time HH:mm] [--quarantine]
OpenSecurity.Cli.exe schedule disable
OpenSecurity.Cli.exe schedule status
OpenSecurity.Cli.exe watch [folder...] [--quarantine]     # real-time protection in the foreground
```

To scan an entire drive, just point it at the root: `OpenSecurity.Cli.exe C:\ --quarantine`

## Code signing

Release exes are signed with a self-signed certificate — see [`signing/README.md`](signing/README.md) for how to regenerate it or swap in a CA-issued certificate. A self-signed certificate proves the signature pipeline works and makes the exe tamper-evident, but it does **not** stop Windows SmartScreen warnings for anyone downloading the exe — only a certificate from a trusted CA does that, and those cost money and require identity verification.

## Status

This is a personal/educational project, not a replacement for a commercial antivirus. Real-time protection is a user-mode folder watcher, not a kernel-mode filter driver — it can't intercept execution the way a real AV's minifilter does, but it does catch files as they land in watched folders.

## Testing

Includes the standard [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) in `test-samples/` as a safe way to verify detection works.
