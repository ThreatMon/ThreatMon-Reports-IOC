rule ConnectWise_Shellcode_Dropper
{
    meta:
        description = "Detects ConnectWise-related shellcode patterns with high confidence"
        author = "Aziz Kaplan"
	mail = "aziz.kaplan@threatmonit.io"
        date = "2025-04-16"
        severity = "high"
        confidence = "85"
    strings:
        $api_call1 = { ff 15 ?? f? 43 00 85 c0 74 ?? } 
        $api_call2 = { ff 75 ?? 57 6a 01 ff 15 ?? f0 43 00 8b f8 85 ff } 
        $api_call3 = { ?? ?? 56 6a 01 57 ff 75 ?? ff 15 ?? f0 43 00 } 
        
        $mem_op1 = { 57 ff 15 ?? f0 43 00 8b 7d ?? }
        $mem_op2 = { ff 77 04 8b 35 ?? f0 43 00 ff 37 68 ?? 64 44 00 } 
        $mem_op3 = { ff d6 8b f8 8b 45 ?? ff 70 04 ff 30 68 ?? 64 44 00 }
        
        $loader1 = { 68 ?? 64 44 00 ff 15 ?? f0 43 00 68 ?? 64 44 00 } 
        $loader2 = { c7 45 ?? 15 00 00 40 c7 45 ?? 01 00 00 00 } 
        $loader3 = { 89 45 ?? ff 15 ?? f0 43 00 8b f0 8d 45 ?? 89 45 ?? } 
        
        $proc_mgmt1 = { ff 15 ?? f? 43 00 8b f0 8b 85 ?? ?? ?? ?? 83 f? ff 75 ?? } 
        $proc_mgmt2 = { 75 ?? 8b 10 8b 40 04 8b 8d ?? ?? ?? ?? } 
        $proc_mgmt3 = { 68 40 9c 00 00 ff 15 ?? f0 43 00 85 ?? 74 ?? } 
        
        $iat_ref = { ?? f0 43 00 }
        
        $str1 = "CertCreateCertificateContext" ascii wide 
        $str2 = "LoadLibraryA" ascii wide 
        $str3 = "CertDeleteCertificateFromStore" ascii wide
	$str4 = "IsDebuggerPresent" ascii wide
	$str5 = "CertCloseStore" ascii wide
	$str6 = "CryptMsgGetParam" ascii wide
	$str7 = "LoadLibraryExW" ascii wide
        $str8 = "Sleep" ascii wide
		
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and 
        filesize < 5MB and
        (
            10 of ($api_call*, $mem_op*, $loader*, $proc_mgmt*) and
            #iat_ref > 10 and
            7 of ($str*)
        )
}