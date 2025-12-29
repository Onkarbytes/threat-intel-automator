rule suspicious_strings {
    meta:
        description = "Detects suspicious strings commonly found in malware"
        author = "SOC Pipeline"
        date = "2025-12-27"

    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "net user" nocase
        $s4 = "reg add" nocase

    condition:
        any of them
}

rule potential_malware {
    meta:
        description = "Generic malware detection pattern"
        author = "SOC Pipeline"
        severity = "medium"

    strings:
        $mz = { 4D 5A }  // MZ header
        $s1 = "CreateProcess" nocase
        $s2 = "VirtualAlloc" nocase
        $s3 = "WriteProcessMemory" nocase

    condition:
        $mz at 0 and 2 of ($s1, $s2, $s3)
}