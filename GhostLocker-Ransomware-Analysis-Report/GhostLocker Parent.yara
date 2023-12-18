import "hash"
rule GhostLocker{
    meta:
    author = "Kerime Gencay"
    description = "GhostLocker Ransomware Rule"
    file_name = "zncxtdvfxpndbwab.exe"
    hash = "81a136029d29d26920c0287faf778776"


strings:
    $str1 = "NUITKA_ONEFILE_PARENT"
    $str2 = "CreateProcessW"
    $str3 = "omni callsig"


    $opc1 = {FF 15 A1 4D 01 00 4C 8B F0 48 83 F8 FF 0F 84 01 02 00 00 48 85 FF 74 56 0F 1F 80 00 00 00 00 BB 00 80 00 00 48 8D 0D F4 32 02 00 48 3B FB 0F 46 DF 48 63 F3 48 8B D6}
    $opc2 = {4C 8D 4C 24 60 44 89 7C 24 60 44 8B C3 4C 89 7C 24 20 48 8D 15 CA 32 02 00 49 8B CE FF 15 19 4D 01 00 85 C0 0F 84 A8 01 00 00 48 2B FE 75 B4 8D 77 5C 49 8B CE FF 15 58 4D 01 00}


condition:
    uint16(0) == 0x5A4D and (any of ($str*,$opc*))
}
