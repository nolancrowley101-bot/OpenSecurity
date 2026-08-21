using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    private const long OverlayThresholdBytes = 1_048_576; // 1 MB - self-extracting installers legitimately have large overlays too, so this is a low-weight signal

    /// <param name="filePath">Used only for Authenticode chain validation; pass null to skip that check (e.g. when only bytes are available).</param>
    public IEnumerable<ScanFinding> Analyze(PeFile pe, byte[] fileBytes, string? filePath = null)
    {
        var score = 0;
        var reasons = new List<string>();

        if (!pe.HasSecurityDirectory)
        {
            score += 5;
            reasons.Add("no embedded Authenticode signature");
        }
        else if (filePath is not null && !IsAuthenticodeChainTrusted(filePath))
        {
            score += 15;
            reasons.Add("Authenticode signature present but does not chain to a trusted root (self-signed, expired, or tampered)");
        }

        foreach (var section in pe.Sections)
        {
            if (section.IsExecutable && section.IsWritable)
            {
                score += 20;
                reasons.Add($"section '{section.Name}' is both writable and executable");
            }

            if (PackerSignatures.KnownPackerSectionNames.Contains(section.Name))
            {
                score += 20;
                reasons.Add($"section name '{section.Name}' matches a known packer/protector");
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

        var overlaySize = ComputeOverlaySize(pe, fileBytes);
        if (overlaySize >= OverlayThresholdBytes)
        {
            score += 8;
            reasons.Add($"{overlaySize:N0} bytes of data appended after the last section/signature (overlay) - can indicate a bundled payload");
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

        var networkHits = importedNames.Count(n => SuspiciousApis.NetworkExfiltration.Contains(n));
        if (networkHits >= 2)
        {
            score += 10;
            reasons.Add($"imports {networkHits} network API(s)");
        }

        if (networkHits >= 1 && injectionHits >= 1)
        {
            score += 20;
            reasons.Add("combines network access with process-injection APIs - a common backdoor/RAT pattern");
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

    private static long ComputeOverlaySize(PeFile pe, byte[] fileBytes)
    {
        long accountedEnd = pe.Sections.Count > 0
            ? pe.Sections.Max(s => (long)s.PointerToRawData + s.RawSize)
            : 0;

        if (pe.HasSecurityDirectory)
            accountedEnd = Math.Max(accountedEnd, (long)pe.SecurityDirectoryFileOffset + pe.SecurityDirectorySize);

        return Math.Max(0, fileBytes.LongLength - accountedEnd);
    }

    private static bool IsAuthenticodeChainTrusted(string filePath)
    {
        try
        {
            // CreateFromSignedFile is obsolete (SYSLIB0057) for general cert loading, but
            // X509CertificateLoader has no equivalent for extracting the Authenticode signer
            // embedded in a signed PE - this remains the correct API for that specific purpose.
#pragma warning disable SYSLIB0057
            using var signerCert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using var cert2 = new X509Certificate2(signerCert);
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(cert2);
        }
        catch (Exception ex) when (ex is CryptographicException or IOException)
        {
            // Signature present but unparseable/corrupt - treat the same as "not trusted"
            // rather than silently skipping, since a malformed signature is itself suspicious.
            return false;
        }
    }
}
