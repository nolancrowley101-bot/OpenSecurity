using OpenSecurity.Core.Scanning;

namespace OpenSecurity.Core.Rules;

public sealed class PatternRuleEngine
{
    private readonly List<PatternRule> _rules;

    public PatternRuleEngine(List<PatternRule> rules)
    {
        _rules = rules;
    }

    public int RuleCount => _rules.Count;

    public IEnumerable<ScanFinding> Scan(ReadOnlySpan<byte> content)
    {
        var findings = new List<ScanFinding>();

        foreach (var rule in _rules)
        {
            var matchedIds = new List<string>();
            foreach (var pattern in rule.Patterns)
            {
                if (pattern.Kind == PatternKind.Ascii && pattern.NoCase
                        ? ContainsCaseInsensitiveAscii(content, pattern.Bytes)
                        : IndexOf(content, pattern.Bytes) >= 0)
                {
                    matchedIds.Add(pattern.Id);
                }
            }

            var isMatch = rule.Condition == RuleCondition.AllOfThem
                ? matchedIds.Count == rule.Patterns.Count
                : matchedIds.Count > 0;

            if (!isMatch)
                continue;

            var verdict = Enum.TryParse<Verdict>(rule.Severity, ignoreCase: true, out var parsed)
                ? parsed
                : Verdict.Suspicious;

            findings.Add(new ScanFinding(
                Source: "rules",
                Verdict: verdict,
                Name: rule.Name,
                Detail: $"matched pattern(s): {string.Join(", ", matchedIds)}",
                Score: verdict == Verdict.Malicious ? 80 : 40));
        }

        return findings;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.Length == 0)
            return -1;
        return haystack.IndexOf(needle);
    }

    private static bool ContainsCaseInsensitiveAscii(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> lowerNeedle)
    {
        if (lowerNeedle.Length == 0 || haystack.Length < lowerNeedle.Length)
            return false;

        for (var i = 0; i <= haystack.Length - lowerNeedle.Length; i++)
        {
            var matched = true;
            for (var j = 0; j < lowerNeedle.Length; j++)
            {
                var b = haystack[i + j];
                if (b is >= (byte)'A' and <= (byte)'Z')
                    b = (byte)(b + 32);
                if (b != lowerNeedle[j])
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
                return true;
        }
        return false;
    }
}
