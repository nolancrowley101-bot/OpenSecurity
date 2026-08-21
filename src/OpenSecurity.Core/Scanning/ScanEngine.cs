using System.Collections.Concurrent;
using OpenSecurity.Core.Hashing;
using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.MachO;
using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Rules;
using SharpCompress.Archives;
using SharpCompress.Readers;

namespace OpenSecurity.Core.Scanning;

public sealed class ScanEngine
{
    private const long MaxFileSizeBytes = 200L * 1024 * 1024; // 200 MB safety cap
    private const int MaxArchiveEntries = 2000;
    private const long MaxArchiveEntryBytes = 50L * 1024 * 1024; // per-entry cap, smaller than the top-level cap since archives are more zip-bomb-prone
    private const long MaxArchiveTotalBytes = 500L * 1024 * 1024; // total decompressed budget across the whole archive
    private const int MaxArchiveDepth = 5; // archive-in-archive-in-archive... guard against unbounded recursion/zip bombs
    private const int FuzzyMatchThreshold = 70; // 0-100 similarity score; below this, two files are treated as unrelated

    private readonly HashScanner _hashScanner;
    private readonly PatternRuleEngine _ruleEngine;
    private readonly HeuristicAnalyzer _heuristicAnalyzer;
    private readonly HashSignatureDatabase _allowlist;
    private readonly IReadOnlyList<string> _archivePasswords;
    private readonly FuzzySignatureDatabase _fuzzySignatures;

    public ScanEngine(HashScanner hashScanner, PatternRuleEngine ruleEngine, HeuristicAnalyzer heuristicAnalyzer,
        HashSignatureDatabase? allowlist = null, IReadOnlyList<string>? archivePasswords = null,
        FuzzySignatureDatabase? fuzzySignatures = null)
    {
        _hashScanner = hashScanner;
        _ruleEngine = ruleEngine;
        _heuristicAnalyzer = heuristicAnalyzer;
        _allowlist = allowlist ?? HashSignatureDatabase.Empty();
        _archivePasswords = archivePasswords ?? Array.Empty<string>();
        _fuzzySignatures = fuzzySignatures ?? FuzzySignatureDatabase.Empty();
    }

    public ScanResult ScanFile(string path)
    {
        var fileInfo = new FileInfo(path);

        if (!fileInfo.Exists)
        {
            var missing = new ScanResult { FilePath = path, FileSizeBytes = 0, Sha256 = "" };
            missing.Findings.Add(new ScanFinding("engine", Verdict.Error, "file-not-found", "file does not exist", 0));
            return missing;
        }

        if (fileInfo.Length > MaxFileSizeBytes)
        {
            var tooLarge = new ScanResult { FilePath = path, FileSizeBytes = fileInfo.Length, Sha256 = "" };
            tooLarge.Findings.Add(new ScanFinding("engine", Verdict.Error, "file-too-large", $"skipped, exceeds {MaxFileSizeBytes / 1024 / 1024} MB scan limit", 0));
            return tooLarge;
        }

        byte[] fileBytes;
        try
        {
            fileBytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            var error = new ScanResult { FilePath = path, FileSizeBytes = fileInfo.Length, Sha256 = "" };
            error.Findings.Add(new ScanFinding("engine", Verdict.Error, "read-error", ex.Message, 0));
            return error;
        }

        var (sha256, findings) = ScanContent(fileBytes, path);
        var result = new ScanResult { FilePath = path, FileSizeBytes = fileBytes.LongLength, Sha256 = sha256 };
        result.Findings.AddRange(findings);

        if (IsSupportedArchiveMagic(fileBytes))
            ScanArchiveEntries(fileBytes, result);

        return result;
    }

    /// <summary>Scans every file under a directory, running scans across multiple CPU cores in
    /// parallel (bounded by <paramref name="maxDegreeOfParallelism"/>, defaulting to the machine's
    /// core count) while still streaming results back as they complete, so callers driving a live
    /// UI keep getting incremental updates instead of waiting for the whole directory to finish.
    /// Results arrive in completion order, not filesystem order.</summary>
    public IEnumerable<ScanResult> ScanDirectory(string directoryPath, bool recursive = true, int? maxDegreeOfParallelism = null)
    {
        if (!Directory.Exists(directoryPath))
        {
            var missing = new ScanResult { FilePath = directoryPath, FileSizeBytes = 0, Sha256 = "" };
            missing.Findings.Add(new ScanFinding("engine", Verdict.Error, "directory-not-found", "directory does not exist", 0));
            yield return missing;
            yield break;
        }

        using var results = new BlockingCollection<ScanResult>(boundedCapacity: 64);

        var producer = Task.Run(() =>
        {
            try
            {
                var options = new ParallelOptions { MaxDegreeOfParallelism = maxDegreeOfParallelism ?? Math.Max(1, Environment.ProcessorCount) };
                Parallel.ForEach(ResilientFileWalker.EnumerateFiles(directoryPath, recursive), options, file =>
                {
                    ScanResult result;
                    try
                    {
                        result = ScanFile(file);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        result = new ScanResult { FilePath = file, FileSizeBytes = 0, Sha256 = "" };
                        result.Findings.Add(new ScanFinding("engine", Verdict.Error, "scan-error", ex.Message, 0));
                    }
                    results.Add(result);
                });
            }
            finally
            {
                results.CompleteAdding();
            }
        });

        foreach (var result in results.GetConsumingEnumerable())
            yield return result;

        producer.GetAwaiter().GetResult(); // re-throw anything Parallel.ForEach itself couldn't hand off per-item
    }

    /// <summary>Runs the hash/allowlist/rule/heuristic pipeline against a blob of bytes, whether it's
    /// a real file on disk or an in-memory archive entry. <paramref name="filePathForAuthenticode"/>
    /// is null for archive entries, since Authenticode validation needs a real file path.</summary>
    private (string Sha256, List<ScanFinding> Findings) ScanContent(byte[] bytes, string? filePathForAuthenticode)
    {
        var sha256 = HashScanner.ComputeSha256(new MemoryStream(bytes));
        var findings = new List<ScanFinding>();

        var exactHashFindings = _hashScanner.Scan(sha256).ToList();
        findings.AddRange(exactHashFindings);

        // An explicit known-malicious hash match always stands; the allowlist only suppresses
        // the noisier pattern-rule/heuristic layers, so it can't be used to hide a blacklisted file.
        if (_allowlist.TryMatch(sha256, out _))
            return (sha256, findings);

        // Fuzzy (context-triggered piecewise) hashing catches near-duplicates - a recompiled
        // sample or a repacked installer - that an exact SHA-256 match would miss entirely.
        // Skipped when an exact match already fired, since that's a stronger, cheaper result.
        if (exactHashFindings.Count == 0 && _fuzzySignatures.Count > 0)
        {
            var fuzzyHash = FuzzyHash.Compute(bytes);
            foreach (var (label, score) in _fuzzySignatures.FindSimilar(fuzzyHash, FuzzyMatchThreshold))
            {
                findings.Add(new ScanFinding("fuzzy-hash", Verdict.Suspicious, label,
                    $"{score}% similar to known-malicious sample signature", score));
            }
        }

        findings.AddRange(_ruleEngine.Scan(bytes));

        if (PeParser.TryParse(bytes, out var peFile) && peFile is not null)
            findings.AddRange(_heuristicAnalyzer.Analyze(peFile, bytes, filePathForAuthenticode));
        else if (MachOParser.TryParse(bytes, out var machOFile) && machOFile is not null)
            findings.AddRange(_heuristicAnalyzer.AnalyzeMachO(machOFile, bytes));

        return (sha256, findings);
    }

    private static bool IsSupportedArchiveMagic(byte[] bytes)
    {
        if (bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] is 0x03 or 0x05 or 0x07 && bytes[3] is 0x04 or 0x06 or 0x08)
            return true; // zip

        if (bytes.Length >= 6 && bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC && bytes[3] == 0xAF && bytes[4] == 0x27 && bytes[5] == 0x1C)
            return true; // 7z

        return false;
    }

    /// <summary>
    /// Opens zip/7z archives - including password-protected ones, common for malware sample
    /// collections shared this way to prevent AV auto-deletion/accidental execution - and scans
    /// every entry with the same pipeline as a real file. Tries no password first, then each
    /// entry in the configured password list, so it also handles unencrypted archives cheaply.
    /// </summary>
    private void ScanArchiveEntries(byte[] archiveBytes, ScanResult result, int depth = 0, string entryPathPrefix = "")
    {
        if (depth >= MaxArchiveDepth)
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "archive-too-deep",
                $"[{entryPathPrefix}] stopped after {MaxArchiveDepth} nested archive levels", 0));
            return;
        }

        var candidatePasswords = new List<string?> { null };
        candidatePasswords.AddRange(_archivePasswords);
        Exception? lastFailure = null;

        foreach (var password in candidatePasswords)
        {
            IArchive archive;
            try
            {
                var stream = new MemoryStream(archiveBytes);
                var options = password is null ? new ReaderOptions() : new ReaderOptions { Password = password };
                archive = ArchiveFactory.OpenArchive(stream, options);
            }
            catch (Exception ex)
            {
                // Not this format, or this password attempt failed outright - try the next candidate.
                if (lastFailure is not NotSupportedException)
                    lastFailure = ex;
                continue;
            }

            using (archive)
            {
                // For 7z, decryption happens at the folder/header level, so a wrong password can
                // throw as soon as entries are enumerated - not just when reading an entry's stream
                // (unlike zip, where each entry is independently encrypted). Validate both steps
                // under the same catch so either format's failure mode moves on to the next password.
                List<IArchiveEntry> entries;
                byte[]? firstEntryBytes;
                try
                {
                    entries = archive.Entries.Where(e => !e.IsDirectory).ToList();
                    if (entries.Count == 0)
                        return; // nothing to scan, whether or not the archive is encrypted

                    using var firstStream = entries[0].OpenEntryStream();
                    firstEntryBytes = ReadBounded(firstStream, MaxArchiveEntryBytes);
                }
                catch (Exception ex)
                {
                    // Wrong password (or a corrupt/unsupported entry) - try the next candidate password.
                    // NotSupportedException means the password actually got past decryption into a
                    // codec we can't decode (e.g. LZMA+AES zip, an uncommon variant) - more informative
                    // than a generic wrong-password failure, so it takes priority when reported below.
                    if (lastFailure is not NotSupportedException)
                        lastFailure = ex;
                    continue;
                }

                long totalBytesRead = 0;
                if (firstEntryBytes is not null)
                {
                    totalBytesRead += firstEntryBytes.LongLength;
                    ProcessEntry(entries[0].Key ?? "?", firstEntryBytes, result, depth, entryPathPrefix);
                }
                else
                {
                    result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-too-large",
                        $"[{entries[0].Key}] exceeds {MaxArchiveEntryBytes / 1024 / 1024} MB, skipped", 0));
                }

                for (var i = 1; i < entries.Count; i++)
                {
                    if (i >= MaxArchiveEntries)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "too-many-entries", $"stopped after {MaxArchiveEntries} entries", 0));
                        break;
                    }

                    if (totalBytesRead >= MaxArchiveTotalBytes)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "archive-too-large", $"stopped after {MaxArchiveTotalBytes / 1024 / 1024} MB of decompressed content", 0));
                        break;
                    }

                    var entry = entries[i];
                    byte[]? entryBytes;
                    try
                    {
                        using var entryStream = entry.OpenEntryStream();
                        entryBytes = ReadBounded(entryStream, MaxArchiveEntryBytes);
                    }
                    catch (Exception ex)
                    {
                        // Some curated malware collections repackage third-party installers inside
                        // the archive, each keeping its own original password instead of the
                        // collection's own convention - a single zip can genuinely mix passwords
                        // per entry. Before giving up on this entry, retry it against every other
                        // configured password (a fresh archive open each time, since a failed
                        // decrypt/decompress can't be resumed mid-entry on the same stream).
                        entryBytes = TryReadEntryWithOtherPasswords(archiveBytes, entry.Key, password, candidatePasswords);
                        if (entryBytes is null)
                        {
                            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-read-error", $"[{entry.Key}] {ex.Message}", 0));
                            continue;
                        }
                    }

                    if (entryBytes is null)
                    {
                        result.Findings.Add(new ScanFinding("archive", Verdict.Error, "entry-too-large", $"[{entry.Key}] exceeds {MaxArchiveEntryBytes / 1024 / 1024} MB, skipped", 0));
                        continue;
                    }

                    totalBytesRead += entryBytes.LongLength;
                    ProcessEntry(entry.Key ?? "?", entryBytes, result, depth, entryPathPrefix);
                }

                return; // found a working password (or the archive wasn't encrypted) - done
            }
        }

        if (lastFailure is NotSupportedException)
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "unsupported-archive",
                $"could not open - uses a compression/encryption combination this version doesn't support ({lastFailure.Message})", 0));
        }
        else
        {
            result.Findings.Add(new ScanFinding("archive", Verdict.Error, "password-protected",
                "could not open - password-protected with an unknown password, or corrupt. Add the password to signatures/archive_passwords.txt to scan it.", 0));
        }
    }

    /// <summary>Scores one archive entry against the full pipeline, then - if the entry is itself
    /// an archive (a zip nested inside a zip, common when malware collections repackage third-party
    /// installers) - recurses into it too, up to <see cref="MaxArchiveDepth"/> levels deep. Entry
    /// names accumulate into a "outer.zip > inner.zip > payload.exe" path so nested findings stay
    /// traceable to where they actually live.</summary>
    private void ProcessEntry(string entryName, byte[] entryBytes, ScanResult result, int depth, string pathPrefix)
    {
        var fullName = string.IsNullOrEmpty(pathPrefix) ? entryName : $"{pathPrefix} > {entryName}";

        var (_, entryFindings) = ScanContent(entryBytes, null);
        foreach (var finding in entryFindings)
            result.Findings.Add(new ScanFinding("archive", finding.Verdict, finding.Name, $"[{fullName}] {finding.Detail}", finding.Score));

        if (IsSupportedArchiveMagic(entryBytes))
            ScanArchiveEntries(entryBytes, result, depth + 1, fullName);
    }

    /// <summary>Retries a single archive entry (matched by key) against every password other than
    /// the one already locked in for the rest of the archive, re-opening a fresh archive/stream
    /// per attempt. Returns null if none of them can decrypt/decompress it.</summary>
    private static byte[]? TryReadEntryWithOtherPasswords(byte[] archiveBytes, string? entryKey, string? alreadyTried, List<string?> candidatePasswords)
    {
        if (entryKey is null)
            return null;

        foreach (var password in candidatePasswords)
        {
            if (password == alreadyTried)
                continue;

            try
            {
                var stream = new MemoryStream(archiveBytes);
                var options = password is null ? new ReaderOptions() : new ReaderOptions { Password = password };
                using var archive = ArchiveFactory.OpenArchive(stream, options);
                var entry = archive.Entries.FirstOrDefault(e => !e.IsDirectory && e.Key == entryKey);
                if (entry is null)
                    continue;

                using var entryStream = entry.OpenEntryStream();
                var bytes = ReadBounded(entryStream, MaxArchiveEntryBytes);
                if (bytes is not null)
                    return bytes;
            }
            catch
            {
                // Wrong password for this entry too - try the next candidate.
            }
        }

        return null;
    }

    /// <summary>Reads a stream into a byte array, returning null instead of exceeding <paramref name="maxBytes"/>
    /// - guards against zip-bomb entries that lie about their declared uncompressed size.</summary>
    private static byte[]? ReadBounded(Stream stream, long maxBytes)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > maxBytes)
                return null;
        }
        return buffer.ToArray();
    }
}
