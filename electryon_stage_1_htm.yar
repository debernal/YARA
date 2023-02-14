rule electryon_stage_1_htm {
	meta:
        author = "David Bernal"
        description = "First stage .htm file delivered as attachment in phishing emails. The file drops Electryon VBS as second stage."
	  hash1 = "7c15020e6ad2f9d6fcdb9b7c76eebb38"
	  hash2 = "6cffea7f9b54bbac3f1e8b7e7d437fc2"
	strings:
		$s1 = "URL = \"h\";"
		$s2 = "URL += \"t\";"
		$s3 = "URL += \"p\";"
		$s4 = "<META name=Generator content="
		$s5 = "var meta = document.createElement('meta');"
		$s6 = "meta.content"
		$s7 = "meta.name"
		$s8 = "document.getElementsByTagName('head')[0].appendChild(meta);"
		$s9 = "location.href=URL;"
	condition:
		filesize < 1KB and
		all of them
}