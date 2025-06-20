rule PulsarRat_Packed_Detection {
    meta:
        description = "YARA Rule for packed Pulsar RAT."
        author = "Seyyit Unutmaz"
        email = "seyyit.unutmaz@threatmonit.io"
        date = "2025-05-30"
        
    strings:
        $str1 = "DeflateStream" ascii
        $str2 = "MemoryStream" ascii 
        $str3 = "GetManifestResourceStream" ascii
        $str4 = "AesManaged" ascii 
        $str5 = "PaddingMode" ascii 
        $str6 = "MethodBase" ascii 
        $str7 = "SymmetricAlgorithm" ascii 
        $str8 = "CompressionMode" ascii 
		
        $hex1 = {2520010000006F1100000A}
        $hex2 = {2520020000006F1200000A}
        $hex3 = {25FE090100280F00000AFE090200280F00000A6F1300000A}
        $hex4 = {FE090000280F00000AFE0E0000}
        $hex5 = {731000000A}
        $hex6 = {280400000A72010000707233000070}
        $hex7 = {728D00007028030000066F0500000A0A}
        $hex8 = {730600000A0B}
        $hex9 = {0616730700000A0C}
        $hex10 = {25FE0C00002000000000FE0C00008E696F1400000AFE0E0100}
 
    condition:
        uint16(0) == 0x5A4D and filesize > 1MB and 7 of ($str*) and all of ($hex*)
}
