import "hash" 
rule APT36_RAT_Detector
{ 
meta: 
description = "APT36_RAT_Detector" 
author = "ThreatMon" 
file_name = "idtvivrs vdao.exe" 
date = "07/07/2023" 
md5 = "DCD66EF46CBFCE8E464D6383A20349ED" 
strings: 
$str1 = "66.154.103.101" 
$str2 = "procAloop"
$a_pdb = "101.115.102.107|"
condition: 
any of ($str*)
}