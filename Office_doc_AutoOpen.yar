rule Office_doc_AutoOpen
{
	meta:
		author = "David Bernal"
		description = "Detects Microsoft Office documents with macro code, shell and function names related to automatic code execution"
	strings:
		$auto1 = "AutoOpen"
		$auto2 = "AutoClose"
		$auto3 = "Document_Open"
		$code1 = "ThisDocument"
		$code2 = "Project"
		$exec1 = ".Run"
		$exec2 = ".ShellExecute"
	condition:
		uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and
		all of ($code*) and 1 of ($auto*) and 1 of ($exec*)
}