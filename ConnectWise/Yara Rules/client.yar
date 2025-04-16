// This file may also detect the legimite ConnectWise Remote Desktop application. Therefore, make sure that ConnectWise is not being used for Remote Desktop operations within the organization before blocking it.

rule ScreenConnect_Connectwise_Client
{
    meta:
        description = "Detects ScreenConnect-Connectwise-Client with high confidence"
        author = "Aziz Kaplan"
	mail = "aziz.kaplan@threatmonit.io"
        date = "2025-04-16"
        severity = "high"
        confidence = "85"
        
    strings:
        $hex1 = {13 30 03 00 41 00 00 00 01 00 00 11 03 75 35 00 00 1B}
        $hex2 = {02 7B 6D 01 00 04 6F 2C 07 00 0A 2A}
        $hex3 = {02 7B 6D 01 00 04 03 6F 2D 07 00 0A 2A}
        $hex4 = {03 2C 06 03 17 33 02 17 2A 16 2A}
        $hex5 = {38 9F 00 00 00 28 4E 01 00 0A 6F D2 01 00 0A}
        $hex6 = {02 07 28 31 07 00 0A 28 0C 04 00 06 2D 3A 02}
        
        $hex7 = {19 8D 26 00 00 01 25 16 72 8E 23 00 70 18 8D 9B}
        $hex8 = {00 00 01 25 16 12 00 FE 15 36 01 00 01 06}
        $hex9 = {8C 36 01 00 01 A2 25 17 12 01 FE 15 37 01 00 01 07 8C}
        
        $hex10 = {04 02 7E 9B 02 00 04 25 2D 17 26 7E 99 02 00 04}
        $hex11 = {FE 06 37 07 00 06 73 41 01 00 0A 25 80 9B 02 00 04}
        $hex12 = {28 E6 03 00 0A 2A 00 1B 30 04 00 3A 00 00}
        
        $process_hollowing = {73 ?? ?? ?? 0A 7E ?? ?? ?? 04 28 ?? ?? ?? 0A 28 ?? ?? ?? 0A}
        $memory_allocation = {72 ?? ?? ?? 70 ?? ?? ?? ?? 28 ?? ?? ?? 0A 80 ?? ?? ?? 04}
        $api_hashing = {25 16 6F ?? ?? ?? 0A 26 1F ?? 28 ?? ?? ?? 0A}
        
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 1MB and
        (
            9 of ($hex*) or 
            (6 of ($hex*) and 1 of ($process_hollowing, $memory_allocation, $api_hashing)) or
            ($hex1 and $hex3 and $hex5 and $hex7 and $hex11 and $hex12)
        )
}
