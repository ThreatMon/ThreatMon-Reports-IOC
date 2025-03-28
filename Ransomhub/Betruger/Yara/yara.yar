rule Betruger_Backdoor_YaraRule {
    meta:
        description = "Enhanced YARA rule for detecting Betruger Backdoor used by Ransomhub"
        author = "Aziz Kaplan"
        email = "aziz.kaplan@threatmonit.io"
        reference = "https://threatmonit.io/"
        threat_level = 10
        severity = "critical"
        family = "Ransomhub.Betruger"
        tlp = "GREEN"
        mitre_att = "T1486, T1490, T1083, T1057, T1082"

    strings:
        $str1 = "Avast Antivirus" wide ascii
        $str2 = "avast-av" wide ascii
        $str3 = "IDI_ASWAVBOOTTIMESCANSHMIN" wide ascii
        $str4 = "AV Boot-time Scanner" wide ascii
        
        $str5 = "Windows Registry Editor" wide ascii
        $str6 = "lifetime_creation_monitor_holder" wide ascii
        $str7 = "/runassvc /winre" wide ascii nocase
        
        $op1 = {4? 8d 4c ?4 40 e8 26 18 00 00}
        $op2 = {80 7d c8 00 75 09 4? 8b cf 4? 89 4d c0}
        $op3 = {ff 15 7f b1 0b 00 85 c0 74 08 8b c8 ff 15 db b5 0b 00}
        $op4 = {ff 15 af 54 0b 00 85 c0 74 2d 4? 8d 4c ?4 60}
        
        $op5 = {4? 8d 84 ?4 c8 00 00 00 4? 89 44 ?4 28}
        $op6 = {ff 15 6d 2f 06 00 85 c0 0f 84 dd 00 00 00}
        
        $op7 = {4? 8d 4d 70 4? c7 45 70 00 00 00 00 ff 15 3c 99 05 00}
        $op8 = {4? 8d 55 78 ?? ?? ?? ?? ?? ff 15 26 90 05 00}
        
        $op9 = {4? 8d 44 ?4 30 ba 08 00 00 00}
        $op10 = {4? c7 44 ?4 30 00 00 00 00 ff 15 67 7e 05 00}
        
        $op11 = {ba ff ff ff ff 4? 8b ca 4? 8b c2 4? 8b cf ff 15 cf b9 06 00}
        $op12 = {ff 15 67 bb 06 00 4? 8b d8 4? 89 45 0f}
        
        $op13 = {ff 15 74 5a 05 00 4? 8d 0d 0d ee 08 00 4? 89 4c ?4 20}
        
        $op14 = {4? 8d 57 40 4? 8d 4d e0 ff 15 6b a8 05 00}
        $op15 = {4? 8d 15 58 20 09 00 4? 8d 4d e0 e8 43 89 03 00}
        
        $op16 = {4? 8b d0 4? 8b ce ff 15 4d 17 08 00}

    condition:
        uint16(0) == 0x5A4D and
        filesize > 5MB and filesize < 10MB and
        (
            (all of ($op*) and all of ($str*))
            or
            (all of ($op*) and 4 of ($str*))
            or
            all of ($op*)
        )
}