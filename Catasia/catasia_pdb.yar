rule Catasia_PDB_Paths{
	meta:
		author = "David Bernal"
		description = "Catasia banker pdb paths"
		reference = "https://blog.scilabs.mx/threat-analysis-catasia/"
	strings:
		$s1 = "c:\\Users\\W7\\Downloads\\kur\\KeyRedirEx\\KeyRedirEx\\obj\\Debug\\KeyRedirEx.pdb" nocase
		$s2 = "C:\\vted\\CeLoa\\Release\\bay.pdb" nocase
	condition:
		any of them
}