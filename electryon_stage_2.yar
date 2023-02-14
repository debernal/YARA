rule electryon_stage_2{
  meta:
        author = "David Bernal"
        description = "Second stage of Electryon VBS dropper delivered through phishing campaign"
	  hash1 = "80f5d36dff464c8675a6e5f06f6c402d"
  strings:
        $a1 = "<component id=\"component2\">"
        $h1 = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>"
        $h2 = "<script language=\"VBScript\">"
        $h3 = "<![CDATA["
        $h4 = "</component>"
        $h5 = "</script>"
        $s1 = ".ExecQuery"
        $s2 = ".Properties_"
        $s3 = "createobject"
        $s4 = ".createTextFile"
        $s5 = "Select Case"
        $s6 = ".expandEnvironmentStrings"
        $s7 = ".ShellExecute"
        $s8 = "]]>"
  condition:
        filesize < 40KB and
        (all of ($h*) and ($a1 and 3 of ($s*) or 8 of ($s*)))
}