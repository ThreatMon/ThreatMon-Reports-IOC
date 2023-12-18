import "hash"
rule GhostLocker{
    meta:
    author = "Kerime Gencay"
    description = "GhostLocker Ransomware Rule"
    file_name = "zncxtdvfxpndbwab.exe"
    hash = "dfbaa667c07fdd5ad2543ce98d097027"


strings:
    $str1 = "cryptography.fernet"
    $str2 = "cryptography.hazmat.primitives.asymmetric.rsa"
    $str3 = "nuitka_module_loader"
    $str4 = "zstandard.backend_cffi"
    $str5 = "cryptography.hazmat.bindings._rust"


    $opc1 = {48 8B CF FF 15 AC 37 02 00 48 FF C7 48 89 45 20 48 03 FB 41 80 FC 61}
    $opc2 = {48 8B 0D 23 5C 02 00 48 8D 15 44 9D 02 00 FF 15 BE 5B 02 00 48 8B 0D 0F 5C 02 00 48 8D 15 C4 73 02 00 48 89 05 19 35 08 00 FF 15 A3 5B 02 00 }
    $opc3 = {FF 15 FE 16 05 00 B1 01 E8 67 FA 02 00 48 8B C8 FF 15 AE 16 05 00 48 8B 05 9F 17 05 00}


condition:
    uint16(0) == 0x5A4D and (any of ($str*,$opc*))
}
