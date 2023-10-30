rule Serpent_Stealer {
    meta:
        author = "Seyit (@mseyit_) - ThreatMon"
        description = "Detects the newly discovered stealer named Serpent"
        date = "30.10.2023"
        hash = "c4f981f1f532ec827032775c88a45f1b4153c3d27885f189654ad6ee85c709c1"
        
    strings:
        $s1 = "Software\\Microsoft\\FTP" wide
        $s2 = "SELECT * FROM autofill" wide
        $s3 = "https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/?key=" wide
        $s4 = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" wide
        $s5 = "DECRYPTED TOKEN :" wide
	$s6 = "http://checkip.dyndns.org/" wide
        
    condition:
	    uint16(0) == 0x5A4D and
	    filesize < 1MB and
	    all of them
}