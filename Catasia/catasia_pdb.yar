Catasia_pdb_paths{
	    meta:
		author = "David Bernal"
		description = "Catasia banker pdb paths"
		reference = "https://blog.scilabs.mx/threat-analysis-catasia/"
	strings:
		$s1 = "c:\\Users\\W7\\Downloads\\kur\\KeyRedirEx\\KeyRedirEx\\obj\\Debug\\KeyRedirEx.pdb"
		$s2 = "C:\\vted\\CeLoa\\Release\\bay.pdb"
	condition:
		any of them
}