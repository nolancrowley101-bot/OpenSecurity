using System.Text;
using System.Text.RegularExpressions;

namespace OpenSecurity.Core.Rules;

/// <summary>
/// Parses a small subset of YARA rule syntax — enough for straightforward string/hex
/// signatures, not a full YARA grammar (no wildcards, regex strings, or nested booleans).
///
/// rule RuleName : severity
/// {
///     strings:
///         $s1 = "some string" ascii
///         $s2 = "wide string" wide nocase
///         $h1 = { 4D 5A 90 00 }
///     condition:
///         any of them
/// }
/// </summary>
public static class PatternRuleParser
{
    private static readonly Regex RuleHeaderRegex = new(
        @"^rule\s+(?<name>\w+)(\s*:\s*(?<severity>\w+))?\s*\{?\s*$", RegexOptions.Compiled);

    private static readonly Regex StringDefRegex = new(
        "^\\$(?<id>\\w+)\\s*=\\s*(?<body>\"(?:[^\"\\\\]|\\\\.)*\"|\\{[^}]*\\})\\s*(?<mods>[\\w\\s]*)$",
        RegexOptions.Compiled);

    public static List<PatternRule> ParseFile(string path) => ParseText(File.ReadAllText(path));

    public static List<PatternRule> ParseDirectory(string directoryPath, string searchPattern = "*.yar")
    {
        var rules = new List<PatternRule>();
        if (!Directory.Exists(directoryPath))
            return rules;

        foreach (var file in Directory.EnumerateFiles(directoryPath, searchPattern, SearchOption.AllDirectories))
            rules.AddRange(ParseFile(file));

        return rules;
    }

    public static List<PatternRule> ParseText(string text)
    {
        var rules = new List<PatternRule>();
        var lines = text.Replace("\r\n", "\n").Split('\n');

        for (var i = 0; i < lines.Length; i++)
        {
            var headerMatch = RuleHeaderRegex.Match(lines[i].Trim());
            if (!headerMatch.Success)
                continue;

            var name = headerMatch.Groups["name"].Value;
            var severity = headerMatch.Groups["severity"].Success ? headerMatch.Groups["severity"].Value : "Suspicious";
            var patterns = new List<RulePattern>();
            var condition = RuleCondition.AnyOfThem;
            var inStrings = false;

            i++;
            if (!lines[i - 1].TrimEnd().EndsWith('{'))
            {
                // opening brace is on its own line (or the next non-blank line) rather than the header line
                while (i < lines.Length && lines[i].Trim().Length == 0)
                    i++;
                if (i < lines.Length && lines[i].Trim() == "{")
                    i++;
            }

            for (; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line == "}")
                    break;
                if (line == "strings:")
                {
                    inStrings = true;
                    continue;
                }
                if (line == "condition:")
                {
                    inStrings = false;
                    continue;
                }
                if (line.StartsWith("all of them", StringComparison.OrdinalIgnoreCase))
                {
                    condition = RuleCondition.AllOfThem;
                    continue;
                }
                if (line.StartsWith("any of them", StringComparison.OrdinalIgnoreCase))
                {
                    condition = RuleCondition.AnyOfThem;
                    continue;
                }
                if (inStrings && line.Length > 0)
                {
                    var pattern = ParseStringDef(line);
                    if (pattern is not null)
                        patterns.Add(pattern);
                }
            }

            if (patterns.Count > 0)
                rules.Add(new PatternRule(name, severity, patterns, condition));
        }

        return rules;
    }

    private static RulePattern? ParseStringDef(string line)
    {
        var match = StringDefRegex.Match(line);
        if (!match.Success)
            return null;

        var id = match.Groups["id"].Value;
        var body = match.Groups["body"].Value;
        var mods = match.Groups["mods"].Value;
        var noCase = mods.Contains("nocase", StringComparison.OrdinalIgnoreCase);
        var wide = mods.Contains("wide", StringComparison.OrdinalIgnoreCase);

        if (body.StartsWith('{'))
        {
            var hex = body.Trim('{', '}').Trim();
            var bytes = ParseHexBytes(hex);
            return bytes is null ? null : new RulePattern(id, PatternKind.Hex, hex, false, bytes);
        }

        var raw = Regex.Unescape(body[1..^1]);
        var encoding = wide ? Encoding.Unicode : Encoding.ASCII;
        var bytesFromString = encoding.GetBytes(noCase ? raw.ToLowerInvariant() : raw);
        return new RulePattern(id, wide ? PatternKind.Wide : PatternKind.Ascii, raw, noCase, bytesFromString);
    }

    private static byte[]? ParseHexBytes(string hex)
    {
        var tokens = hex.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var bytes = new byte[tokens.Length];
        for (var i = 0; i < tokens.Length; i++)
        {
            if (!byte.TryParse(tokens[i], System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                return null;
        }
        return bytes;
    }
}
