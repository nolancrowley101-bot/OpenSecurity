namespace OpenSecurity.Core.Pe;

public sealed record PeSection(string Name, uint VirtualSize, uint VirtualAddress, uint RawSize, uint PointerToRawData, uint Characteristics)
{
    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
}

public sealed record PeImport(string DllName, string FunctionName);

public sealed record PeFile(
    bool Is64Bit,
    ushort Machine,
    uint EntryPointRva,
    uint SizeOfImage,
    bool HasSecurityDirectory,
    IReadOnlyList<PeSection> Sections,
    IReadOnlyList<PeImport> Imports);
