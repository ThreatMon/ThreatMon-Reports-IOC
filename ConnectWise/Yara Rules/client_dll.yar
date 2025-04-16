// This file may also detect the legimite ConnectWise Remote Desktop application. Therefore, make sure that ConnectWise is not being used for Remote Desktop operations within the organization before blocking it.

rule ConnectWise_Client_DLL {
    meta:
        description = "Detects ConnectWise Client DLL with high accuracy"
        author = "Aziz Kaplan"
	mail = "aziz.kaplan@threatmonit.io"
        date = "2025-04-16"
        severity = "high"
        confidence = "95"

    strings:
        // Core binary patterns identified in malicious ConnectWise DLLs
        $hex1 = {5D0900706F7600000A26}
        $hex2 = {0F000328060200062A}
        $hex3 = {03755D0000022C0D0203A55D00000228060200062A162A}
        $hex4 = {06727F0900706F7600000A26}
        $hex5 = {0203280A02000616FE012A}
        $hex6 = {0672090700706F7600000A26}
        $hex7 = {02191616285402000A}
        $hex8 = {036F460400060A1200285502000A72311800702848}
        $hex9 = {0672FB0500706F7600000A}
        $hex10 = {0672CF0300706F7600000A26}
        $hex11 = {0672C50800706F7600000A26}
        $hex12 = {FE16AB00001B6F1400000ADC0228C301000A2A000110000002001100192A00}
        $hex13 = {000A173317080416941203FE15B500001B096FE401000A38}
        
        // Additional MSIL bytecode patterns characteristic of malicious ConnectWise samples
        $msil_ptrn1 = {28??000006??2800000006}
        $msil_ptrn2 = {062D??280?0000??2A}
        
        // Network-related function signatures
        $net_sig1 = {06720?0?00706F??00000A}
        $net_sig2 = {2?6F??0?000?7D??00000?}
        
        // Common assembly references found in malicious samples
        $assembly = "Assembly-CSharp" ascii wide nocase
        $connect = "ConnectWise" ascii wide nocase
        $remote = "RemoteControl" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and  // PE file check
        (
            all of ($hex*) or
            (9 of ($hex*) and (all of ($msil_ptrn*) or all of ($net_sig*))) or
            (7 of ($hex*) and 2 of ($msil_ptrn*) and 1 of ($assembly, $connect, $remote))
        )
}
