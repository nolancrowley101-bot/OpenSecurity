namespace OpenSecurity.Core.Heuristics;

/// <summary>
/// Windows API functions frequently seen in process injection, code manipulation,
/// or anti-analysis techniques. Presence alone is not proof of malice (plenty of
/// legitimate software calls these) — used only as heuristic scoring signal.
/// </summary>
public static class SuspiciousApis
{
    public static readonly IReadOnlySet<string> ProcessInjection = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "QueueUserAPC", "SetThreadContext", "ResumeThread", "NtUnmapViewOfSection",
        "RtlCreateUserThread", "NtWriteVirtualMemory", "NtMapViewOfSection"
    };

    public static readonly IReadOnlySet<string> AntiAnalysis = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter"
    };

    public static readonly IReadOnlySet<string> CredentialAccess = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CryptUnprotectData", "LsaRetrievePrivateData", "SamIConnect", "CredEnumerateA", "CredEnumerateW"
    };

    public static readonly IReadOnlySet<string> DynamicLoading = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll"
    };

    public static readonly IReadOnlySet<string> NetworkExfiltration = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetReadFile", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
        "HttpSendRequestA", "HttpSendRequestW", "socket", "connect", "send", "recv", "WSAStartup"
    };
}
