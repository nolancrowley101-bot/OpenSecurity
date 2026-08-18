# OpenSecurity

An on-demand malware scanner for Windows, built from scratch in C#/.NET.

By **Nolan Crowley**. Open source under the [MIT License](LICENSE).

## What it does

OpenSecurity scans a file or folder using three detection layers:

- **Hash signatures** — SHA-256 exact match against a known-bad hash list (`signatures/hashes.txt`)
- **Pattern rules** — simplified YARA-style string/hex matching (`rules/*.yar`)
- **Heuristics** — a from-scratch PE (Portable Executable) header parser that scores packing signs (high-entropy sections), RWX sections, missing Authenticode signatures, and suspicious API imports (process injection, anti-debugging, credential access)

No external antivirus/YARA native dependencies — everything is self-contained managed code.

## Projects

- `src/OpenSecurity.Core` — the scan engine (hashing, rules, PE parsing, heuristics)
- `src/OpenSecurity.Cli` — command-line scanner
- `src/OpenSecurity.Ui` — WPF desktop app (dark theme, drag-and-drop, live results)
- `tests/OpenSecurity.Core.Tests` — unit tests for the engine

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

Drop more SHA-256 hashes into `signatures/hashes.txt`, or more `.yar` rule files into `rules/` — both load at runtime, no rebuild needed.

## Status

This is a personal/educational project, not a replacement for a commercial antivirus. Currently on-demand scanning only; scheduled scanning and real-time protection are potential future additions.

## Testing

Includes the standard [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) in `test-samples/` as a safe way to verify detection works.
