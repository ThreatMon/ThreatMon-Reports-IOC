import "hash" 
rule NestJS_Detector
{ 
meta: 
description = "APT36_RAT_Detector" 
author = "ThreatMon" 
file_name = "9fd5b84656b2a.exe" 
date = "04/08/2023" 
md5 = "	db2c2fccb99e5ea0b710fda6423eda8c" 
strings: 
$str1 = "SELECT * FROM cookies" 
$str2 = "PgIZJW1tQEFDZVVJUnx+cGRYXGNtcFtKRw=="
$str3 = "sqlite3_open"
$str4 = "credit_cards"
$str5 = "card_number_encrypted"
$str6 = "name_on_card"
$str7 = "expiration_month"
$str8 = "expiration_year"
$str9 = "moz_cookies"
condition: 
7 of ($str*)
}