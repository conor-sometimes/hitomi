rule eicar : test canary
{
    meta:
        description = "EICAR standard antivirus test string (benign canary, not malware)"
        author      = "hitomi tests"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        // A distinctive substring of the EICAR signature, not the full 68-char
        // string, so this rule file is not itself an antivirus hit. Any file
        // containing the real EICAR string contains this substring.
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
