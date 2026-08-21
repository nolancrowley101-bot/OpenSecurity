using System.Text;
using OpenSecurity.Core.MachO;
using Xunit;

namespace OpenSecurity.Core.Tests;

public class MachOParserTests
{
    private static byte[] BuildThinMachO64(uint initprot = 0x5 /* r+x */, string dylibPath = "/usr/lib/libSystem.B.dylib", bool codeSignature = false)
    {
        var dylibBytes = Encoding.ASCII.GetBytes(dylibPath);
        var dylibNameLen = dylibBytes.Length + 1; // + null terminator
        var dylibCmdSize = 24 + dylibNameLen;

        var ncmds = codeSignature ? 3 : 2;
        var sizeofcmds = 72 + dylibCmdSize + (codeSignature ? 16 : 0);

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        w.Write(0xFEEDFACFu); // magic (LE)
        w.Write(0x01000007u); // cputype: CPU_TYPE_X86_64
        w.Write(0x3u);        // cpusubtype
        w.Write(0x2u);        // filetype: MH_EXECUTE
        w.Write((uint)ncmds);
        w.Write((uint)sizeofcmds);
        w.Write(0x0u);        // flags
        w.Write(0x0u);        // reserved

        // LC_SEGMENT_64 "__TEXT"
        w.Write(0x19u);       // cmd
        w.Write(72u);         // cmdsize
        var segname = new byte[16];
        Encoding.ASCII.GetBytes("__TEXT").CopyTo(segname, 0);
        w.Write(segname);
        w.Write(0x100000000UL); // vmaddr
        w.Write(0x1000UL);      // vmsize
        w.Write(0UL);            // fileoff
        w.Write(0x1000UL);      // filesize
        w.Write(0x7u);          // maxprot
        w.Write(initprot);      // initprot
        w.Write(0u);            // nsects
        w.Write(0u);            // flags

        // LC_LOAD_DYLIB
        w.Write(0xCu);              // cmd
        w.Write((uint)dylibCmdSize);
        w.Write(24u);               // name offset (from start of this load command)
        w.Write(0u);                // timestamp
        w.Write(0u);                // current_version
        w.Write(0u);                // compatibility_version
        w.Write(dylibBytes);
        w.Write((byte)0);

        if (codeSignature)
        {
            w.Write(0x1Du); // LC_CODE_SIGNATURE
            w.Write(16u);   // cmdsize
            w.Write(0u);    // dataoff
            w.Write(0u);    // datasize
        }

        // pad out to cover the declared filesize of the __TEXT segment so slicing doesn't go out of bounds
        var bytes = ms.ToArray();
        var padded = new byte[Math.Max(bytes.Length, 0x1000)];
        bytes.CopyTo(padded, 0);
        return padded;
    }

    [Fact]
    public void TryParse_ParsesMinimalThinMachO64()
    {
        var bytes = BuildThinMachO64();

        var ok = MachOParser.TryParse(bytes, out var machO);

        Assert.True(ok);
        Assert.NotNull(machO);
        Assert.True(machO!.Is64Bit);
        Assert.Single(machO.Segments);
        Assert.Equal("__TEXT", machO.Segments[0].Name);
        Assert.Single(machO.LoadedDylibs);
        Assert.Equal("/usr/lib/libSystem.B.dylib", machO.LoadedDylibs[0]);
        Assert.False(machO.HasCodeSignature);
    }

    [Fact]
    public void TryParse_DetectsCodeSignaturePresence()
    {
        var bytes = BuildThinMachO64(codeSignature: true);

        var ok = MachOParser.TryParse(bytes, out var machO);

        Assert.True(ok);
        Assert.True(machO!.HasCodeSignature);
    }

    [Fact]
    public void TryParse_DetectsRwxSegment()
    {
        var bytes = BuildThinMachO64(initprot: 0x7 /* r+w+x */);

        MachOParser.TryParse(bytes, out var machO);

        Assert.True(machO!.Segments[0].IsExecutable);
        Assert.True(machO.Segments[0].IsWritable);
    }

    [Fact]
    public void TryParse_ReturnsFalse_ForNonMachOData()
    {
        var bytes = "this is not a Mach-O file at all, just plain text padding"u8.ToArray();
        var ok = MachOParser.TryParse(bytes, out var machO);
        Assert.False(ok);
        Assert.Null(machO);
    }

    [Fact]
    public void TryParse_ReturnsFalse_ForTruncatedHeader()
    {
        var bytes = new byte[] { 0xCF, 0xFA, 0xED, 0xFE }; // magic only, LE bytes of 0xFEEDFACF
        var ok = MachOParser.TryParse(bytes, out var machO);
        Assert.False(ok);
        Assert.Null(machO);
    }

    [Fact]
    public void TryParse_NeverThrows_OnRandomGarbageWithMachOMagic()
    {
        var random = new Random(42);
        var bytes = new byte[4096];
        random.NextBytes(bytes);
        BitConverter.GetBytes(0xFEEDFACFu).CopyTo(bytes, 0);

        var exception = Record.Exception(() => MachOParser.TryParse(bytes, out _));
        Assert.Null(exception);
    }

    [Fact]
    public void TryParse_ParsesFatBinary_ContainingThinSlice()
    {
        var thin = BuildThinMachO64();

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(0xCAFEBABEu)); // FAT_MAGIC, big-endian on disk
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(1u));          // nfat_arch
        // fat_arch: cputype, cpusubtype, offset, size, align - all big-endian
        var fatArchStart = 8;
        var thinOffset = 4096; // 8-byte aligned slice offset
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(0x01000007u));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(3u));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)thinOffset));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness((uint)thin.Length));
        w.Write(System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(12u));
        _ = fatArchStart;

        var header = ms.ToArray();
        var fat = new byte[thinOffset + thin.Length];
        header.CopyTo(fat, 0);
        thin.CopyTo(fat, thinOffset);

        var ok = MachOParser.TryParse(fat, out var machO);

        Assert.True(ok);
        Assert.NotNull(machO);
        Assert.Single(machO!.LoadedDylibs);
    }
}
