rule Ransomware_Chaos
{ 
meta: 
description = "Chaos Ransomware Detector" 
author = "ThreatMon" 
file_name = "warthundercrackfulltank.exe" 
date = "25/08/2023" 
md5 = "b6201731829cbee98a7b14a6e68b74da" 
strings: 
$str1 = "decryption software, this software will allow you to recover all of your data and remove the"
$str2 = "AES_Encrypt"
$str3 = "FromBase64String"
$str4 = "commands"
$str5 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete"
$str6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no"
$str7 = "wbadmin delete catalog -quiet.jpg"
$str8 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$str9 = "warthundercrackfulltank.exe"
$str10 = "<encryptDirectory>b__2"
$str11 = "read_it.txt"
$str12 = "!This program cannot be run in DOS mode."
$str13 = "All of your files have been encrypted"
condition: 
4 of ($str*)
}