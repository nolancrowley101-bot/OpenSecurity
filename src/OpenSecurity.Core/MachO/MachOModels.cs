namespace OpenSecurity.Core.MachO;

public sealed record MachOSegment(string Name, ulong VmAddress, ulong VmSize, uint FileOffset, uint FileSize, uint InitialProtection, uint MaxProtection)
{
    // vm_prot_t bits: VM_PROT_READ = 0x1, VM_PROT_WRITE = 0x2, VM_PROT_EXECUTE = 0x4
    public bool IsWritable => (InitialProtection & 0x2) != 0;
    public bool IsExecutable => (InitialProtection & 0x4) != 0;
}

public sealed record MachOFile(
    bool Is64Bit,
    uint CpuType,
    uint FileType,
    bool HasCodeSignature,
    IReadOnlyList<MachOSegment> Segments,
    IReadOnlyList<string> LoadedDylibs);
