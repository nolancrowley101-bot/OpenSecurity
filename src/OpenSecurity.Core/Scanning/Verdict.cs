namespace OpenSecurity.Core.Scanning;

// Ordered by increasing severity so ScanResult can take the max across findings;
// Error ranks above Clean but below any actual detection so it never masks a real hit.
public enum Verdict
{
    Clean,
    Error,
    Suspicious,
    Malicious
}
