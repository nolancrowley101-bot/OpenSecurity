using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.Heuristics;

/// <summary>
/// Scores PE files on structural traits associated with packing, obfuscation, or
/// process-injection tooling. Purely heuristic: individual signals are weak and common
/// in legitimate software too, so findings are Suspicious, not Malicious, until the
/// combined score crosses a high threshold.
/// </summary>
public sealed class HeuristicAnalyzer
{
    private const double HighEntropyThreshold = 7.2;
    private const int SuspiciousScoreThreshold = 30;
    private const int MaliciousScoreThreshold = 60;

    public IEnumerable<ScanFinding> Analyze(PeFile pe, byte[] fileBytes)
    {
        var score = 0;
        var reasons = new List<string>();

        if (!pe.HasSecurityDirectory)
        {
            score += 5;
            reasons.Add("no embedded Authenticode signature");
        }

        foreach (var section in pe.Sections)
        {
            if (section.IsExecutable && section.IsWritable)
            {
                score += 20;
                reasons.Add($"section '{section.Name}' is both writable and executable");
            }

            if (section.RawSize > 0 && section.PointerToRawData + section.RawSize <= fileBytes.Length)
            {
                var sectionBytes = fileBytes.AsSpan((int)section.PointerToRawData, (int)section.RawSize);
                var entropy = Entropy.Shannon(sectionBytes);
                if (entropy >= HighEntropyThreshold)
                {
                    score += 15;
                    reasons.Add($"section '{section.Name}' has high entropy ({entropy:F2}) suggesting packing/encryption");
                }
            }
        }

        if (pe.Sections.Count == 0)
        {
            score += 10;
            reasons.Add("no sections found");
        }

        var importedNames = pe.Imports.Select(i => i.FunctionName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var injectionHits = importedNames.Count(n => SuspiciousApis.ProcessInjection.Contains(n));
        if (injectionHits >= 2)
        {
            score += 20 + injectionHits * 5;
            reasons.Add($"imports {injectionHits} process-injection-related API(s)");
        }

        var antiAnalysisHits = importedNames.Count(n => SuspiciousApis.AntiAnalysis.Contains(n));
        if (antiAnalysisHits >= 2)
        {
            score += 10;
            reasons.Add($"imports {antiAnalysisHits} anti-debugging API(s)");
        }

        var credAccessHits = importedNames.Count(n => SuspiciousApis.CredentialAccess.Contains(n));
        if (credAccessHits >= 1)
        {
            score += 15;
            reasons.Add($"imports {credAccessHits} credential-access API(s)");
        }

        var dynamicLoadOnly = importedNames.Count(n => SuspiciousApis.DynamicLoading.Contains(n));
        if (dynamicLoadOnly >= 2 && pe.Imports.Count <= 6)
        {
            score += 10;
            reasons.Add("relies almost entirely on dynamic API resolution (LoadLibrary/GetProcAddress) with few static imports");
        }

        if (score == 0)
            yield break;

        var verdict = score >= MaliciousScoreThreshold
            ? Verdict.Malicious
            : score >= SuspiciousScoreThreshold
                ? Verdict.Suspicious
                : Verdict.Clean;

        if (verdict == Verdict.Clean)
            yield break;

        yield return new ScanFinding(
            Source: "heuristic",
            Verdict: verdict,
            Name: "heuristic-pe-analysis",
            Detail: string.Join("; ", reasons) + $" (score: {score})",
            Score: score);
    }
}
