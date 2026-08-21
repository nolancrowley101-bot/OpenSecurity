using System.Buffers.Binary;
using System.Text;

namespace OpenSecurity.Core.MachO;

/// <summary>
/// Minimal, defensive Mach-O (macOS executable) header parser. Only extracts the fields needed
/// for heuristic analysis (segments, loaded dylibs, code signature presence). Never throws on
/// malformed input - returns false instead, since scanned files may be truncated or corrupt.
///
/// Scope: parses native little-endian thin binaries (MH_MAGIC / MH_MAGIC_64 - what every Intel
/// and Apple Silicon Mac produces) and FAT_MAGIC universal binaries wrapping them, which covers
/// the overwhelming majority of real-world macOS malware. The reverse-endian "CIGAM" variants
/// (relevant only to now-defunct PowerPC targets) and the arm64e-only FAT_MAGIC_64 extension are
/// deliberately not supported - real samples using either are vanishingly rare.
/// </summary>
public static class MachOParser
{
    private const uint MhMagic64 = 0xFEEDFACF;
    private const uint MhMagic32 = 0xFEEDFACE;
    private const uint FatMagic = 0xCAFEBABE;
    private const uint LcSegment = 0x1;
    private const uint LcSegment64 = 0x19;
    private const uint LcLoadDylib = 0xC;
    private const uint LcLoadWeakDylib = 0x80000018;
    private const uint LcReexportDylib = 0x8000001F;
    private const uint LcLoadUpwardDylib = 0x80000023;
    private const uint LcCodeSignature = 0x1D;
    private const int MaxLoadCommands = 1024;
    private const int MaxFatArches = 8;

    public static bool TryParse(byte[] data, out MachOFile? machOFile)
    {
        machOFile = null;
        try
        {
            return TryParseCore(data, out machOFile);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or EndOfStreamException)
        {
            return false;
        }
    }

    private static bool TryParseCore(byte[] data, out MachOFile? machOFile)
    {
        machOFile = null;
        if (data.Length < 4)
            return false;

        var magic = BinaryPrimitives.ReadUInt32BigEndian(data);
        if (magic == FatMagic)
            return TryParseFat(data, out machOFile);

        var magicLe = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (magicLe is MhMagic32 or MhMagic64)
            return TryParseThin(data, 0, out machOFile);

        return false;
    }

    private static bool TryParseFat(byte[] data, out MachOFile? machOFile)
    {
        machOFile = null;
        if (data.Length < 8)
            return false;

        var nFatArch = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4, 4));
        var archCount = (int)Math.Min(nFatArch, MaxFatArches);

        for (var i = 0; i < archCount; i++)
        {
            var archOffset = 8 + i * 20;
            if (archOffset + 20 > data.Length)
                break;

            var fileOffset = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(archOffset + 8, 4));
            var size = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(archOffset + 12, 4));
            if (fileOffset >= data.Length || (long)fileOffset + size > data.Length || size < 4)
                continue;

            // Analyze the first parseable slice - good enough for heuristic scoring, and avoids
            // duplicating findings across near-identical architecture variants of the same binary.
            if (TryParseThin(data, (int)fileOffset, out machOFile))
                return true;
        }

        return false;
    }

    private static bool TryParseThin(byte[] data, int baseOffset, out MachOFile? machOFile)
    {
        machOFile = null;
        if (baseOffset + 4 > data.Length)
            return false;

        var magic = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(baseOffset, 4));
        var is64Bit = magic == MhMagic64;
        if (!is64Bit && magic != MhMagic32)
            return false;

        var headerSize = is64Bit ? 32 : 28;
        if (baseOffset + headerSize > data.Length)
            return false;

        var filetype = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(baseOffset + 12, 4));
        var ncmds = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(baseOffset + 16, 4));
        var sizeofcmds = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(baseOffset + 20, 4));

        var cmdsStart = baseOffset + headerSize;
        if (cmdsStart + sizeofcmds > data.Length)
            return false;

        var segments = new List<MachOSegment>();
        var dylibs = new List<string>();
        var hasCodeSignature = false;

        var offset = cmdsStart;
        var commandsEnd = cmdsStart + (int)sizeofcmds;
        for (var i = 0; i < ncmds && i < MaxLoadCommands && offset + 8 <= commandsEnd; i++)
        {
            var cmd = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            var cmdsize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 4, 4));
            if (cmdsize < 8 || offset + cmdsize > commandsEnd)
                break;

            switch (cmd)
            {
                case LcSegment when offset + 56 <= data.Length:
                    segments.Add(ReadSegment32(data, offset));
                    break;

                case LcSegment64 when offset + 72 <= data.Length:
                    segments.Add(ReadSegment64(data, offset));
                    break;

                case LcLoadDylib or LcLoadWeakDylib or LcReexportDylib or LcLoadUpwardDylib when offset + 24 <= data.Length:
                    var nameOffset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 8, 4));
                    var nameStart = offset + (int)nameOffset;
                    if (nameOffset >= 24 && nameStart < offset + (int)cmdsize && nameStart < data.Length)
                        dylibs.Add(ReadCString(data, nameStart, offset + (int)cmdsize));
                    break;

                case LcCodeSignature:
                    hasCodeSignature = true;
                    break;
            }

            offset += (int)cmdsize;
        }

        machOFile = new MachOFile(is64Bit, 0, filetype, hasCodeSignature, segments, dylibs);
        return true;
    }

    private static MachOSegment ReadSegment32(byte[] data, int offset)
    {
        var name = ReadFixedString(data, offset + 8, 16);
        var vmaddr = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 24, 4));
        var vmsize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 28, 4));
        var fileoff = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 32, 4));
        var filesize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 36, 4));
        var maxprot = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 40, 4));
        var initprot = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 44, 4));
        return new MachOSegment(name, vmaddr, vmsize, fileoff, filesize, initprot, maxprot);
    }

    private static MachOSegment ReadSegment64(byte[] data, int offset)
    {
        var name = ReadFixedString(data, offset + 8, 16);
        var vmaddr = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 24, 8));
        var vmsize = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 32, 8));
        var fileoff = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 40, 8));
        var filesize = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 48, 8));
        var maxprot = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 56, 4));
        var initprot = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 60, 4));
        return new MachOSegment(name, vmaddr, vmsize, (uint)fileoff, (uint)filesize, initprot, maxprot);
    }

    private static string ReadFixedString(byte[] data, int offset, int length)
    {
        var span = data.AsSpan(offset, length);
        var nullIdx = span.IndexOf((byte)0);
        return Encoding.ASCII.GetString(nullIdx >= 0 ? span[..nullIdx] : span);
    }

    private static string ReadCString(byte[] data, int start, int maxEnd)
    {
        var end = start;
        var bound = Math.Min(data.Length, maxEnd);
        while (end < bound && data[end] != 0)
            end++;
        return Encoding.ASCII.GetString(data, start, end - start);
    }
}
