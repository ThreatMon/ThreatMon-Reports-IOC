rule Matanbuchus_Detection
{
    meta:
        description = "Enhanced YARA rule for detecting Matanbuchus 3.0 Loader"
		author = "Seyyit Unutmaz"
		email = seyyit.unutmaz@threatmonit.io"
        date = "2025-08-15"

    strings:
        $c1 = { C7 04 ?? ?? 78 70 61 }
        $c2 = { C7 04 ?? ?? 64 20 33 }
        $c3 = { C7 04 ?? ?? 2D 62 79 }
        $c4 = { C7 04 ?? ?? 65 20 6B }
        $g  = { 6A 33 E8 00 00 00 00 83 04 24 05 CB }

        $o1  = { 83 3D ?? BE 0D 10 00 68 ?? ?? ?? ?? A1 BC BD 0D 10 E8 ?? ?? 00 00 }
        $o2  = { 6A ?? 8D ?? ?? F? FF FF 5? E8 ?? ?? F? FF }
        $o3  = { 8B 45 ?? 83 C0 30 5? 8B 4D ?? 83 E9 30 5? }
        $o4  = { 0F B6 11 81 FA C3 00 00 00 75 ?? EB ?? }
        $o5  = { 8B 45 FC 0F B6 08 81 F9 B8 00 00 00 75 ?? }
        $o6  = { 8B 4D E8 83 C1 02 51 8B 55 EC 52 FF 15 }
        $o7  = { 0F B7 14 41 81 E2 FF 0F 00 00 89 55 E0 83 7D E4 03 75 }
        $o8  = { 68 CC 02 00 00 8D 95 ?? ?? FF FF 52 6A 1D 8B 45 84 50 E8 }
        $o9  = { 8B 8D 78 FF FF FF 51 E8 2D F2 04 00 }
        $o10 = { 8D 85 B0 FB FF FF 50 8B 4D 0C 51 8B 55 08 52 E8 }

        $s1 = "S-1-15-2-191009188" ascii wide
        $s2 = "ResolveDelayLoaded" ascii wide
        $s3 = "\\Devices\\NamedPipe\\" ascii wide
        $s4 = "CoCreateGuid" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 1363149 and all of ($c*) and $g and (7 of ($o*)) and (any of ($s*))
}