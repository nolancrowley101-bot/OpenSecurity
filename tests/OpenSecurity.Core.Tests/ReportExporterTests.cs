using OpenSecurity.Core.Reporting;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class ReportExporterTests : IDisposable
{
    private readonly string _outFile = Path.Combine(Path.GetTempPath(), "OpenSecurityTests_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        foreach (var ext in new[] { ".json", ".csv" })
        {
            var f = _outFile + ext;
            if (File.Exists(f))
                File.Delete(f);
        }
    }

    private static List<ScanResult> SampleResults()
    {
        var clean = new ScanResult { FilePath = "clean.txt", FileSizeBytes = 5, Sha256 = new string('1', 64) };
        var malicious = new ScanResult { FilePath = "bad, with a comma.exe", FileSizeBytes = 10, Sha256 = new string('2', 64) };
        malicious.Findings.Add(new ScanFinding("hash", Verdict.Malicious, "known-bad", "matched signature \"X\"", 100));
        return new List<ScanResult> { clean, malicious };
    }

    [Fact]
    public void ExportJson_ProducesParseableJsonWithAllResults()
    {
        var path = _outFile + ".json";
        ReportExporter.ExportJson(SampleResults(), path);

        var parsed = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
        Assert.Equal(2, parsed.RootElement.GetArrayLength());
    }

    [Fact]
    public void ExportCsv_EscapesCommasAndQuotesInFields()
    {
        var path = _outFile + ".csv";
        ReportExporter.ExportCsv(SampleResults(), path);

        var lines = File.ReadAllLines(path);
        Assert.Equal("FilePath,Verdict,Sha256,SizeBytes,Findings", lines[0]);
        Assert.Contains(lines, l => l.Contains("\"bad, with a comma.exe\""));
        Assert.Contains(lines, l => l.Contains("matched signature \"\"X\"\""));
    }

    [Fact]
    public void Export_PicksFormatFromExtension()
    {
        var jsonPath = _outFile + ".json";
        var csvPath = _outFile + ".csv";

        ReportExporter.Export(SampleResults(), jsonPath);
        ReportExporter.Export(SampleResults(), csvPath);

        Assert.StartsWith("[", File.ReadAllText(jsonPath).TrimStart());
        Assert.StartsWith("FilePath,", File.ReadAllText(csvPath));
    }
}
