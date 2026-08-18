namespace OpenSecurity.Core.Scanning;

public sealed record ScanFinding(string Source, Verdict Verdict, string Name, string Detail, int Score);
