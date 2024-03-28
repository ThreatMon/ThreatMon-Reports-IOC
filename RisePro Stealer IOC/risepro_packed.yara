import "hash"
rule RiseProStealer{
    meta:
    author = "Kerime Gencay"
    description = "RisePro Stealer Rule"
    file_name = "RAIDXpert2.exe"
    hash = "7d907dfb44d87310fcd5d7725166491e"
strings:
    $str1 = "StealerClient.exe" 
    $str2 = "InitCommonControls" 
    $str3 = "ihwlqgah" 
    $str4 = "NTA0dJ" 
    $str5 = "F0d2(9k" 
      
    $opc1 = {69 68 77 6C 71 67 61 68}
    $opc2 = {61 74 01 74 24 E4 47 5C 06 7B 3E 6C 33 2B 02 53}
    
condition:
    uint16(0) == 0x5A4D and (any of ($str*,$opc*))
}
