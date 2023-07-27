rule detect_X1na
{
	meta:
		author = "ThreatMon"
		description = "Detects X1na Stealer"
		md5 = "42a1e3b409eedc1e91ddb15a6d974631"

	strings:
		$string1 = "sbiedll" nocase ascii wide
		$string2 = "VklmeGZxcnlVVHlaVUJHRENCQXZiWVZZSXNleElNN1o=" nocase ascii wide
		$string3 = "SbieDll.dll" nocase ascii wide
		$string4 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" nocase ascii wide

	condition:
		all of them
}