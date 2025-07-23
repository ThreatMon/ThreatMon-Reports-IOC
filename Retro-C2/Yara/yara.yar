rule RetroC2_Malware_Detection
{
    meta:
        description = "Detects Retro-C2 RAT & Stealer Malware"
        author = "Seyyit Unutmaz"
        email = "seyyit.unutmaz@threatmonit.io"
        date = "2025-07-21"


    strings:
        $str1 = "\\.\\pipe\\ChromeDecryptIPC_" ascii wide
        $str2 = "PAYLOAD_DLL" ascii
        $str4 = "ChaCha20" ascii
        $str5 = "Reflective DLL" ascii
        $str6 = "ReflectiveLoader" ascii
        $str7 = "RETRO CLIENT" ascii


        $op_01 = { 48 8D 15 2C F6 05 00 48 8D 4D 0F E8 6B A7 00 00 }
        $op_02 = { FF 15 7E E3 04 00 85 C0 79 78 0F 57 C0 }
        $op_03 = { 45 33 C0 48 8D 15 F0 BC 05 00 E8 69 A8 00 00 }
        $op_04 = { 8B C8 48 8D 15 68 C5 04 00 49 03 CD E8 90 28 03 00 }
        $op_05 = { 43 8B 7C 18 2C 41 2B F9 41 03 FA }
        $op_06 = { BB 23 00 00 00 48 89 5C 24 28 4C 8D 3D 31 C3 04 00 }
        $op_07 = { 4C 89 7C 24 20 8B D3 48 8B CF E8 4A BA FF FF 48 8B F8 }
        $op_08 = { 0F 11 84 24 A4 00 00 00 0F 11 84 24 B4 00 00 00 }
        $op_09 = { 4C 8B 7B 08 4C 2B FA 49 8B CE E8 96 78 01 00 }
        $op_10 = { 83 F8 09 0F 86 96 01 00 00 8D 47 BF 83 F8 19 0F 86 8A 01 00 }
        $op_11 = { 80 FA 22 75 1B 41 B8 02 00 00 00 48 8D 15 BC 4A 06 00 }
        $op_12 = { FF 15 3D D4 04 00 8B C8 B8 3B D4 B5 31 F7 E1 }


    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (4 of ($str*)) and
 (10 of ($op_*))
}
