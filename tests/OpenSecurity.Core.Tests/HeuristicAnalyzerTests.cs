using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.Pe;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class HeuristicAnalyzerTests
{
    private readonly HeuristicAnalyzer _analyzer = new();

    private static PeFile MinimalPe(IReadOnlyList<PeSection> sections, IReadOnlyList<PeImport> imports, bool hasSecurityDirectory = true)
        => new(Is64Bit: true, Machine: 0x8664, EntryPointRva: 0x1000, SizeOfImage: 0x2000,
               HasSecurityDirectory: hasSecurityDirectory, SecurityDirectoryFileOffset: 0, SecurityDirectorySize: 0,
               Sections: sections, Imports: imports);

    [Fact]
    public void Analyze_CleanMinimalFile_ProducesNoFindings()
    {
        var pe = MinimalPe(new List<PeSection>(), new List<PeImport>());
        var findings = _analyzer.Analyze(pe, new byte[16]).ToList();
        Assert.Empty(findings);
    }

    // Overlay (+8) and packer-name (+20) are deliberately weak signals per the analyzer's
    // combined-scoring design - neither crosses the 30-point Suspicious threshold alone, so
    // these tests combine them with an RWX section (+20) rather than asserting standalone triggering.

    [Fact]
    public void Analyze_LargeOverlay_ContributesToScore_WhenComboCrossesThreshold()
    {
        const uint rwx = 0x60000020 | 0x80000000; // executable + writable
        var section = new PeSection("UPX1", 0x100, 0x1000, 0x100, 0x200, rwx); // RWX(20) + packer(20) = 40, already Suspicious
        var pe = MinimalPe(new List<PeSection> { section }, new List<PeImport>());

        var withoutOverlay = _analyzer.Analyze(pe, new byte[0x400]).ToList();
        Assert.Single(withoutOverlay);
        Assert.DoesNotContain("overlay", withoutOverlay[0].Detail);

        var withOverlay = _analyzer.Analyze(pe, new byte[2 * 1024 * 1024]).ToList();
        Assert.Single(withOverlay);
        Assert.Contains("overlay", withOverlay[0].Detail);
        Assert.True(withOverlay[0].Score > withoutOverlay[0].Score);
    }

    [Fact]
    public void Analyze_SmallTrailingBytes_DoesNotCountAsOverlay()
    {
        var section = new PeSection("txt", 0x100, 0x1000, 0x100, 0x200, 0x60000020);
        var pe = MinimalPe(new List<PeSection> { section }, new List<PeImport>());
        var bytes = new byte[0x400]; // well under the 1 MB overlay threshold

        var findings = _analyzer.Analyze(pe, bytes).ToList();

        Assert.Empty(findings);
    }

    [Fact]
    public void Analyze_KnownPackerSectionName_ContributesToScore()
    {
        const uint rwx = 0x60000020 | 0x80000000;
        var section = new PeSection("UPX1", 0x1000, 0x1000, 0x1000, 0x400, rwx); // RWX(20) + packer(20) = 40
        var pe = MinimalPe(new List<PeSection> { section }, new List<PeImport>());

        var findings = _analyzer.Analyze(pe, new byte[0x1400]).ToList();

        Assert.Single(findings);
        Assert.Contains("packer", findings[0].Detail);
        Assert.Equal(Verdict.Suspicious, findings[0].Verdict);
    }

    [Fact]
    public void Analyze_NetworkPlusInjectionApis_EscalatesToMalicious()
    {
        var imports = new List<PeImport>
        {
            new("kernel32.dll", "VirtualAllocEx"),
            new("kernel32.dll", "WriteProcessMemory"),
            new("kernel32.dll", "CreateRemoteThread"),
            new("ws2_32.dll", "socket"),
            new("ws2_32.dll", "connect"),
        };
        var pe = MinimalPe(new List<PeSection>(), imports);

        var findings = _analyzer.Analyze(pe, new byte[16]).ToList();

        Assert.Single(findings);
        Assert.Equal(Verdict.Malicious, findings[0].Verdict);
        Assert.Contains("backdoor", findings[0].Detail);
    }

    [Fact]
    public void Analyze_NoAuthenticodeCheck_WhenFilePathNotProvided()
    {
        var pe = MinimalPe(new List<PeSection>(), new List<PeImport>(), hasSecurityDirectory: true);

        // filePath omitted (defaults to null) - must not throw, and must not fabricate a finding
        var findings = _analyzer.Analyze(pe, new byte[16]).ToList();

        Assert.Empty(findings);
    }
}
