import "pe"
import "hash"

rule Detect_Fake_Chrome_ELF_DLL
{
	meta:
    	description = "Detects fake or tampered chrome_elf.dll files"
    	author = "Aziz Kaplan <aziz.kaplan@threatmonit.io>"
    	date = "2025-05-07"
    	reference = "Original chrome_elf.dll file size is 1.54MB"
    	severity = "critical"
	strings:
    	$op1 = { BA 1A 00 00 00 33 C9 FF 15 4D 12 01 00 }
    	$op2 = { 4? 8D 8D 40 01 00 00 E8 23 F5 FF FF }
    	$op3 = { 4? 8D 15 AE 9F 00 00 33 C9 FF 15 8E 10 01 00 }
    	$op4 = { E8 CE F0 FF FF 90 4? 8D A5 C8 00 00 00 }
    	$op5 = { E8 2E F1 FF FF 90 4? 8D A5 C8 00 00 00 }
    	$s1  = "GetInstallDetailsPayload" ascii
	condition:
    	// SHA-256 hash must not match the legitimate file
    	hash.sha256(0, filesize) != "f26b70188c4764a9d28fbcf23e9280d69791729fd37e518ffe5d1b1604ee79e2" and
    	// File size should be outside expected range of the legitimate DLL (1.53-1.60 MB)
    	filesize < 1600000 or filesize > 1677721 and
    	// The PE signature must not be from Google LLC
    	not for any s in pe.signatures : (s.subject contains "Google LLC") and
    	// Opcode and function name must be present
    	all of ($op*) and $s1
}