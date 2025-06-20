rule PulsarRat_Unpacked_Detection {
    meta:
        description = "YARA Rule for unpacked Pulsar RAT."
        author = "Seyyit Unutmaz"
        email = "seyyit.unutmaz@threatmonit.io"
        date = "2025-05-30"
      
    strings:
        $str1 = "costura.pulsar" ascii nocase
        $str2 = "Pulsar.Common" ascii 
        $str3 = "Pulsar.Client" ascii


        $op1_1 = {03161720FF01000028F10400060A}
        $op1_2 = {067E0400000A280500000A2C1C}
        $op1_3 = {037E0400000A7E0400000A1620FF0100007E0400000A28F20400060A}
        $op1_4 = {02067D2E050004}
        $op1_5 = {027B2E05000428F004000626}
        $op1_6 = {28F3040006120128F404000626}
        $op1_7 = {28020500060C}
        $op1_8 = {077B3D0500046B085A69077B3E0500046B085A69735601000A}
        $op1_9 = {0528290500060C05282A0500060D}


        $op2_1 = {7E3D06000428D101000A2C02162A}
        $op2_2 = {7E4A06000473E004000A}
        $op2_3 = {257E??0600046F0507000A80??060004}
        $op2_4 = {7E4E0600046F0507000A287202000A730607000A804F060004}
        $op2_5 = {28DE050006}
        $op2_6 = {28DF0500062A}


        $op3_1 = {020617739702000A}
        $op3_2 = {1602FE06B9010006739802000A739902000A7D0B030004}
        $op3_3 = {027B0B030004036F0B00000A1420000C0000166F9A02000A}
        $op3_4 = {03000416027B0F0300048E6902FE06BA010006}
        $op3_5 = {73F901000A146F9B02000A26}
        $op3_6 = {021728A80100062B06}
 
    condition:
        uint16(0) == 0x5A4D and filesize > 1MB and (2 of ($op1*, $op2*, $op3*) or 2 of ($str1, $str2, $str3))
}
