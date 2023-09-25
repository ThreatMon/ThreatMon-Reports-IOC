rule Kimsuky_Multistaged
{
    meta:
        description = "Kimsuky Multistaged Attack Detection"
        author = "ThreatMon"
        date = "25/09/2023"

    strings:
        $str1 = "register_icmp"
        $str2 = "%s\\Microsoft\\1.tmp"
        $str3 = "%s\\Microsoft\\2.tmp"
        $str4 = "%s\\Microsoft\\1.bat"
        $str5 = "Google Chrome UpdateManager"
        $str6 = "https://drive.google.com/file/d/1KU_YNOIzn94spYf2zbqHhZN8S6Uug6cr/view?usp=sharing"
        $str7 = "cmd.exe /c powershell.exe  cd $env:appdata ;powershell -executionpolicy remotesigned -file \"./colegg.ps1\""
        $str8 = "%appdata%\\..\\..\\downloads\\Updater.zip"
        $str9 = "%appdata%\\..\\..\\downloads\\Google_Chrome_Update_v51.0.0729.87.exe"
        $str10 = "%appdata%\\..\\..\\downloads\\Updater\\Google_Chrome_Update_v51.0.0729.87.exe"
        $str11 = "%appdata%\\..\\..\\downloads\\iphlpapi.dll"
        $str12 = "cmd.exe /c taskkill /im powershell.exe /f"
        $str13 = "https://docs.google.com/document/d/1qCGmSger3Bgvnms_jCABvUdDp5H9trp6IbxVoMhnG7c/edit"

    condition:
        3 of ($str*)
}
