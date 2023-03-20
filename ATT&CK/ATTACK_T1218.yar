rule regsvrExecution : Delivery regsvr32
{
	meta:
		author = "David Bernal"
		description = "Detects regsvr32 scripts with code for command execution. ATT&CK ID: T1218.010 Sub-technique of:  T1218"
		reference = "https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32"
		hash1 = "4c8ef666ff36eb0780dc4cfa7941a7de"
		hash2 = "bb784d55895db10b67b1b4f1f5b0be16"
		hash3 = "59a0c0aeab4a3aa9192973db7d4e2680"
	strings:
		$s1 = "<scriptlet" nocase
		$s2 = "<registration" nocase
		$s3 = "<script language" nocase
		$s4 = "</scriptlet>" nocase
		$s5 = "</registration>" nocase
		$s6 = "</script>" nocase

		$run1 = "ActiveXObject(\"WScript.Shell\").Run(" nocase
		$run2 = "ActiveXObject('WScript.Shell').Run(" nocase
		
		condition:
			filesize < 100KB and

			// <?XML, <?xml file header
			(uint32be(0) == 0x3C3F584D and uint8(4) == 0x4C) or (uint32be(0) == 0x3C3F786D and uint8(4)== 0x6C) and 	
			
			all of ($s*) and 1 of ($run*)
}