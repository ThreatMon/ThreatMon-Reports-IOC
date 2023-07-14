import "hash" 
rule SideCopy_DLL_Rat
{ 
meta: 
description = "SideCopy_DLL_Rat" 
author = "ThreatMon" 
file_name = "DUser.dll" 
date = "14/07/2023" 
md5 = "6b5541136566fdfa69c2e40022845c23" 
strings: 
$str1 = "cpp-httplib/0.7" 
$str2 = "RichX:"
$a_pdb = "multipart/form-data; boundary="
condition: 
all of ($str*)
}