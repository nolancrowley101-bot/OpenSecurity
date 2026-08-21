namespace OpenSecurity.Core.Heuristics;

/// <summary>
/// Section names left behind by well-known executable packers/protectors. Packing alone
/// isn't proof of malice (plenty of legitimate software is packed for size or IP protection),
/// but malware disproportionately uses it to defeat static signature scanning, so it's a
/// useful weak-to-moderate heuristic signal.
/// </summary>
public static class PackerSignatures
{
    public static readonly IReadOnlySet<string> KnownPackerSectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack",
        ".vmp0", ".vmp1", ".vmp2", ".themida", ".petite",
        ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".nsp2", "PECompact2", ".packed"
    };
}
