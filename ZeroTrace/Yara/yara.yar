rule NullPointStealer_ZeroTraceStealer
{
    meta:
        description = "This rule detects both Nullpoint Stealer and ZeroTrace Stealer(Welcome Future) Malware. The rule can be integrated to security solutions to be protected against this emerging threat."
        author = "Aziz Kaplan"
		mail = "aziz.kaplan@threatmonit.io"
        date = "2025-05-09"
        reference = "ThreatMon Malware R&D"
        severity = "critical"
    strings:
        $lInATd = { 160B2B78 }
        $MancrU = { 0C086F3B01000A287600000A2D5E02 }
        $aDjACt = { 1F1A281F00000A7248160070282F00000A0A }
        $hrOnsi = { 1207289100000A110672E2160070 }
        $MuSATE = { 02723A170070282F00000A082883000006284900000A }
        $raCtIo = { 1F1A281F00000A7226150070282F00000A0D }
        $Xcligh = { 0A02724832007028B2000006 }
        $QuiTEs = { 026F1501000A72B22800706F4D00000A }
        $tACiDE = { 257232300070282F00000A28FA0000061307 }
        $exCulU = { 02729428007028B20000060B }
        $koReXM = { 28350000062D37 }
        $neQvSt = { 1A280600000A72E046AA70280700000A06287D00000A }
        $zUpLiK = { 067E220000047E260000046F9400000A }
        $wONaTf = { 070816088E696F2400000A }
        $tREaLM = { 2813000006 }
        $bANxFo = { 281400000628 }
        $mOCvDy = { 1F128D14000001251608720100 }
        $ePYtQa = { 0070280700000AA22517087275000070 }
        $vERdUz = { 280700000AA225180872E3 }
        $dUCzKm = { 000070280700000AA2251909727201 }
        $cALpBx = { 72A084AA7072CA84AA7073D800000A0A }
        $yILqMz = { 7EE000000A72E883AA706FE100000A }
    condition:
        filesize > 200KB and (
            ($lInATd and $MancrU and $aDjACt and $hrOnsi and $MuSATE and $raCtIo and $Xcligh and $QuiTEs and $tACiDE and $exCulU) or
            ($koReXM and $neQvSt and $zUpLiK and $wONaTf and $tREaLM and $bANxFo and $mOCvDy and $ePYtQa and $vERdUz and $dUCzKm and $cALpBx and $yILqMz)
        )
}
