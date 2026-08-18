using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.Reporting;

/// <summary>Writes a completed scan's results to disk as JSON or CSV for record-keeping/sharing.</summary>
public static class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static void Export(IReadOnlyList<ScanResult> results, string path)
    {
        if (path.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
            ExportCsv(results, path);
        else
            ExportJson(results, path);
    }

    public static void ExportJson(IReadOnlyList<ScanResult> results, string path)
    {
        var json = JsonSerializer.Serialize(results, JsonOptions);
        File.WriteAllText(path, json);
    }

    public static void ExportCsv(IReadOnlyList<ScanResult> results, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("FilePath,Verdict,Sha256,SizeBytes,Findings");

        foreach (var result in results)
        {
            var findingsSummary = string.Join("; ", result.Findings.Select(f => $"[{f.Source}] {f.Name}: {f.Detail}"));
            sb.AppendLine(string.Join(',',
                CsvField(result.FilePath),
                CsvField(result.OverallVerdict.ToString()),
                CsvField(result.Sha256),
                CsvField(result.FileSizeBytes.ToString()),
                CsvField(findingsSummary)));
        }

        File.WriteAllText(path, sb.ToString());
    }

    private static string CsvField(string value)
    {
        var escaped = value.Replace("\"", "\"\"");
        return $"\"{escaped}\"";
    }
}
