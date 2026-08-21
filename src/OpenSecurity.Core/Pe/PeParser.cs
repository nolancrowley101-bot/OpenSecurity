using System.Text;

namespace OpenSecurity.Core.Pe;

/// <summary>
/// Minimal, defensive PE (Portable Executable) header parser. Only extracts the fields
/// needed for heuristic analysis (sections, imports, security directory location/size).
/// Never throws on malformed input — returns false instead, since scanned files may be
/// truncated, corrupt, or deliberately malformed.
/// </summary>
public static class PeParser
{
    private const int ImageDirectoryEntryImport = 1;
    private const int ImageDirectoryEntrySecurity = 4;
    private const int MaxImportsCollected = 512;
    private const int MaxImportDescriptors = 256;
    private const int MaxThunksPerDescriptor = 512;

    public static bool TryParse(byte[] data, out PeFile? peFile)
    {
        peFile = null;
        try
        {
            return TryParseCore(data, out peFile);
        }
        catch (Exception ex) when (ex is IndexOutOfRangeException or ArgumentOutOfRangeException or EndOfStreamException)
        {
            return false;
        }
    }

    private static bool TryParseCore(byte[] data, out PeFile? peFile)
    {
        peFile = null;
        if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
            return false;

        var reader = new SafeReader(data);
        var eLfanew = reader.ReadInt32At(0x3C);
        if (eLfanew < 0 || eLfanew + 24 > data.Length)
            return false;

        if (!(data[eLfanew] == 'P' && data[eLfanew + 1] == 'E' && data[eLfanew + 2] == 0 && data[eLfanew + 3] == 0))
            return false;

        var fileHeaderOffset = eLfanew + 4;
        var machine = reader.ReadUInt16At(fileHeaderOffset);
        var numberOfSections = reader.ReadUInt16At(fileHeaderOffset + 2);
        var sizeOfOptionalHeader = reader.ReadUInt16At(fileHeaderOffset + 16);

        var optionalHeaderOffset = fileHeaderOffset + 20;
        if (sizeOfOptionalHeader < 2 || optionalHeaderOffset + sizeOfOptionalHeader > data.Length)
            return false;

        var magic = reader.ReadUInt16At(optionalHeaderOffset);
        var is64Bit = magic == 0x20B;
        if (magic != 0x10B && magic != 0x20B)
            return false;

        var entryPointRva = reader.ReadUInt32At(optionalHeaderOffset + 16);
        var sizeOfImage = reader.ReadUInt32At(optionalHeaderOffset + 56);

        var numberOfRvaAndSizesOffset = optionalHeaderOffset + (is64Bit ? 108 : 92);
        var numberOfRvaAndSizes = reader.ReadUInt32At(numberOfRvaAndSizesOffset);
        var dataDirectoryOffset = numberOfRvaAndSizesOffset + 4;

        (uint Rva, uint Size) ReadDirectory(int index)
        {
            if (index >= numberOfRvaAndSizes)
                return (0, 0);
            var entryOffset = dataDirectoryOffset + index * 8;
            if (entryOffset + 8 > data.Length)
                return (0, 0);
            return (reader.ReadUInt32At(entryOffset), reader.ReadUInt32At(entryOffset + 4));
        }

        var securityDir = ReadDirectory(ImageDirectoryEntrySecurity);
        var importDir = ReadDirectory(ImageDirectoryEntryImport);

        var sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        var sections = new List<PeSection>();
        for (var i = 0; i < numberOfSections; i++)
        {
            var offset = sectionTableOffset + i * 40;
            if (offset + 40 > data.Length)
                break;

            var nameBytes = data.AsSpan(offset, 8);
            var nullIdx = nameBytes.IndexOf((byte)0);
            var name = Encoding.ASCII.GetString(nullIdx >= 0 ? nameBytes[..nullIdx] : nameBytes);

            sections.Add(new PeSection(
                Name: name,
                VirtualSize: reader.ReadUInt32At(offset + 8),
                VirtualAddress: reader.ReadUInt32At(offset + 12),
                RawSize: reader.ReadUInt32At(offset + 16),
                PointerToRawData: reader.ReadUInt32At(offset + 20),
                Characteristics: reader.ReadUInt32At(offset + 36)));
        }

        var imports = ReadImports(reader, data, sections, importDir.Rva, is64Bit);

        // Quirk: for the Security directory (unlike every other data directory), the "RVA" field
        // is actually a raw file offset, not an RVA - the certificate table isn't mapped into memory.
        peFile = new PeFile(is64Bit, machine, entryPointRva, sizeOfImage, securityDir.Size > 0,
            securityDir.Rva, securityDir.Size, sections, imports);
        return true;
    }

    private static List<PeImport> ReadImports(SafeReader reader, byte[] data, List<PeSection> sections, uint importDirRva, bool is64Bit)
    {
        var imports = new List<PeImport>();
        if (importDirRva == 0)
            return imports;

        for (var d = 0; d < MaxImportDescriptors; d++)
        {
            var descOffset = RvaToOffset(sections, importDirRva) + (uint)(d * 20);
            if (descOffset is null || descOffset.Value + 20 > data.Length)
                break;

            var offset = (int)descOffset.Value;
            var originalFirstThunk = reader.ReadUInt32At(offset);
            var nameRva = reader.ReadUInt32At(offset + 12);
            var firstThunk = reader.ReadUInt32At(offset + 16);

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            var dllNameOffset = RvaToOffset(sections, nameRva);
            var dllName = dllNameOffset is null ? "?" : ReadCString(data, dllNameOffset.Value);

            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            var thunkSize = is64Bit ? 8 : 4;
            var ordinalFlag = is64Bit ? 0x8000000000000000UL : 0x80000000UL;

            for (var t = 0; t < MaxThunksPerDescriptor && imports.Count < MaxImportsCollected; t++)
            {
                var thunkOffset = RvaToOffset(sections, thunkRva + (uint)(t * thunkSize));
                if (thunkOffset is null || thunkOffset.Value + thunkSize > data.Length)
                    break;

                var thunkValue = is64Bit ? reader.ReadUInt64At((int)thunkOffset.Value) : reader.ReadUInt32At((int)thunkOffset.Value);
                if (thunkValue == 0)
                    break;

                if ((thunkValue & ordinalFlag) != 0)
                    continue; // imported by ordinal, no name available

                var hintNameOffset = RvaToOffset(sections, (uint)thunkValue);
                if (hintNameOffset is null)
                    continue;

                var funcName = ReadCString(data, hintNameOffset.Value + 2);
                imports.Add(new PeImport(dllName, funcName));
            }

            if (imports.Count >= MaxImportsCollected)
                break;
        }

        return imports;
    }

    private static uint? RvaToOffset(List<PeSection> sections, uint rva)
    {
        if (rva == 0)
            return null;

        foreach (var section in sections)
        {
            var size = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + size)
                return section.PointerToRawData + (rva - section.VirtualAddress);
        }
        return null;
    }

    private static string ReadCString(byte[] data, uint offset)
    {
        if (offset >= data.Length)
            return string.Empty;

        var start = (int)offset;
        var end = start;
        var maxEnd = Math.Min(data.Length, start + 256);
        while (end < maxEnd && data[end] != 0)
            end++;

        return Encoding.ASCII.GetString(data, start, end - start);
    }

    private sealed class SafeReader
    {
        private readonly byte[] _data;
        public SafeReader(byte[] data) => _data = data;

        public ushort ReadUInt16At(int offset) => BitConverter.ToUInt16(_data, offset);
        public int ReadInt32At(int offset) => BitConverter.ToInt32(_data, offset);
        public uint ReadUInt32At(int offset) => BitConverter.ToUInt32(_data, offset);
        public ulong ReadUInt64At(int offset) => BitConverter.ToUInt64(_data, offset);
    }
}
