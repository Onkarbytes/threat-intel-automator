rule network_suspicious {
    meta:
        description = "Detects suspicious network-related strings"
        author = "SOC Pipeline"
        category = "network"

    strings:
        $s1 = "http://" nocase
        $s2 = "https://" nocase
        $s3 = "ftp://" nocase
        $s4 = "irc://" nocase
        $s5 = "wget" nocase
        $s6 = "curl" nocase

    condition:
        3 of them
}

rule encryption_suspicious {
    meta:
        description = "Detects potential encryption/decryption operations"
        author = "SOC Pipeline"
        severity = "high"

    strings:
        $crypto1 = "AES" nocase
        $crypto2 = "RSA" nocase
        $crypto3 = "encrypt" nocase
        $crypto4 = "decrypt" nocase
        $crypto5 = "cipher" nocase

    condition:
        2 of ($crypto*)
}