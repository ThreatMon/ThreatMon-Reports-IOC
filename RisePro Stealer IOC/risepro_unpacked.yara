import "hash"
rule RiseProStealer{
    meta:
    author = "Kerime Gencay"
    description = "RisePro Stealer Rule"
    file_name = "unpacked_RAIDXpert2"
    hash = "50050075a5be50644c7eb93c5eee9504"
strings:
    $str1 = "StealerClient.exe" 
    $str2 = "truncate" 
    $str3 = "https://ipinfo.io/" wide
    $str4 = "https://www.maxmind.com/en/locate-my-ip-address" wide
    $str5 = "RAIDXpert2" 
    $str6 = "RtlUnwind" 
    $str7 = "GdipDisposeImage" 
    $str18 = "XprotExit" 
    $str9 = "coalesce" 
    $str10 = "fullfsync" 
      
    $opc1 = {69 68 77 6C 71 67 61 68}
    $opc2 = {FF 15 60 50 0D 01 85 C0 0F 85 DB FD FF FF FF 15 4C 50 0D 01 83 F8 12 0F 85 CC FD FF FF 57}
    $opc3 = {8D 45 F1 50 56 C6 45 FF 00 FF D7 0F 28 05 C0 68 E5 00 33 C9 A3 38 60 E6 00 0F 11 45 EC C7 45 FC BD 95 00 01 8D 41 C3 30 44 0D EC 41 83 F9 12 72 F3 8D 45 EC C6 45 FF 00 50 56 FF D7}
    
condition:
    uint16(0) == 0x5A4D and (any of ($str*,$opc*))
}
