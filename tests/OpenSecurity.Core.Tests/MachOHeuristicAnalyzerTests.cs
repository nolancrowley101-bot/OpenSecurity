using OpenSecurity.Core.Heuristics;
using OpenSecurity.Core.MachO;
using OpenSecurity.Core.Scanning;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class MachOHeuristicAnalyzerTests
{
    private readonly HeuristicAnalyzer _analyzer = new();

    private static MachOSegment TextSegment(uint initprot, uint fileOffset = 0, uint fileSize = 0)
        => new("__TEXT", VmAddress: 0x100000000, VmSize: 0x1000, FileOffset: fileOffset, FileSize: fileSize, InitialProtection: initprot, MaxProtection: 0x7);

    [Fact]
    public void AnalyzeMachO_CleanMinimalFile_ProducesNoFindings()
    {
        var machO = new MachOFile(true, 0, 2, HasCodeSignature: true, Segments: new List<MachOSegment>(), LoadedDylibs: new List<string>());
        var findings = _analyzer.AnalyzeMachO(machO, new byte[16]).ToList();
        Assert.Empty(findings);
    }

    [Fact]
    public void AnalyzeMachO_RwxSegmentPlusMissingSignature_EscalatesToSuspicious()
    {
        // RWX(20) + no-signature(5) = 25, still below Suspicious(30) alone - combine with a
        // suspicious dylib path (20) to cross the threshold, matching the PE test's approach
        // of combining weak signals rather than asserting a single one crosses on its own.
        var segments = new List<MachOSegment> { TextSegment(initprot: 0x7) }; // r+w+x
        var dylibs = new List<string> { "/tmp/injector.dylib" };
        var machO = new MachOFile(true, 0, 2, HasCodeSignature: false, Segments: segments, LoadedDylibs: dylibs);

        var findings = _analyzer.AnalyzeMachO(machO, new byte[16]).ToList();

        Assert.Single(findings);
        Assert.Equal(Verdict.Suspicious, findings[0].Verdict);
        Assert.Contains("writable and executable", findings[0].Detail);
        Assert.Contains("unusual location", findings[0].Detail);
    }

    [Fact]
    public void AnalyzeMachO_NoSegments_ContributesWeakSignalOnly()
    {
        var machO = new MachOFile(true, 0, 2, HasCodeSignature: false, Segments: new List<MachOSegment>(), LoadedDylibs: new List<string>());

        var findings = _analyzer.AnalyzeMachO(machO, new byte[16]).ToList();

        // no-signature(5) + no-segments(10) = 15, below Suspicious(30) - correctly produces no finding
        Assert.Empty(findings);
    }

    [Fact]
    public void AnalyzeMachO_SuspiciousDylibPath_IsFlaggedByPathShapeNotName()
    {
        Assert.True(MachOHeuristics.IsSuspiciousDylibPath("/tmp/foo.dylib"));
        Assert.True(MachOHeuristics.IsSuspiciousDylibPath("/Users/victim/Downloads/payload.dylib"));
        Assert.True(MachOHeuristics.IsSuspiciousDylibPath("@rpath/../../../tmp/evil.dylib"));
        Assert.False(MachOHeuristics.IsSuspiciousDylibPath("/usr/lib/libSystem.B.dylib"));
        Assert.False(MachOHeuristics.IsSuspiciousDylibPath("@rpath/libfoo.dylib"));
    }
}
