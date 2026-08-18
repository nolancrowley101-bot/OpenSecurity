using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Ui.ViewModels;

public sealed class ScanRowViewModel
{
    public ScanRowViewModel(ScanResult result)
    {
        Result = result;
    }

    public ScanResult Result { get; }

    public string FilePath => Result.FilePath;
    public string Sha256 => Result.Sha256;
    public Verdict Verdict => Result.OverallVerdict;
    public string VerdictLabel => Verdict.ToString().ToUpperInvariant();
    public IReadOnlyList<ScanFinding> Findings => Result.Findings;
    public bool HasFindings => Result.Findings.Count > 0;

    public string SizeLabel => Result.FileSizeBytes >= 1024 * 1024
        ? $"{Result.FileSizeBytes / (1024.0 * 1024.0):F1} MB"
        : $"{Result.FileSizeBytes / 1024.0:F1} KB";
}
