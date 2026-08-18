namespace OpenSecurity.Core.Rules;

public enum PatternKind
{
    Ascii,
    Wide,
    Hex
}

public sealed record RulePattern(string Id, PatternKind Kind, string RawValue, bool NoCase, byte[] Bytes);

public enum RuleCondition
{
    AnyOfThem,
    AllOfThem
}

public sealed record PatternRule(string Name, string Severity, List<RulePattern> Patterns, RuleCondition Condition);
