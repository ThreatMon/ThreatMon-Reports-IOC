rule Konni_Multistaged_Exfiltration
{
    meta:
        description = "Konni Multistaged Attack Detection"
        author = "ThreatMon"
        date = "28/09/2023"

    strings:
        $str1 = "k@J9_@-Xf0hxyOK;."
        $str2 = "WScript.ScriptFullName"
        $str3 = "WScript.Arguments.Item(0)"
        $str4 = "WScript.Arguments.Item(1)"
        $str5 = "eC9NM;['vB{,*"
        $str6 = " %-JlT4D] v%+f"
        $str7 = "[fu Lr#]/n;8"
        $str8 = "http://anrun.kr/movie/contents.php?fifo=%COMPUTERNAME%"
        $str9 = "stopedge.bat"
        $str10 = "activate.vbs"
        $str11 = "MicrosoftEdgeEasyUpdate"
        $str12 = "paycom.ini"
        $str13 = "update.vbs"
        $str14 = "versioninfo.bat"
        $str15 = "=zm32LT_9G1RZlG9'"
        $str16 = " u~1FBC9+s;6ASgH=uY;76%86p"
        $str17 = "gBco4s EmQX*aox'9.wH9Q7SW{eeMVoUI"
        $str18 = "!)('@#7U5{]Y);"
        $str19 = "(K5JXrn-&Qg ~"
        $str20 = "#l-xFhdlT-0{"
		$str21 = "cuserdown.data"
		$str22 = "cuserdocu.data"
		$str23 = "cuserdesk.data"
		$str24 = "cprog.data"
		$str25 = "cprog32.data"
		$str26 = "ipinfo.data"
		$str27 = "tsklt.data"
		$str28 = "systeminfo.data"

    condition:
        3 of them
}
