rule hidden_iframe {
	meta:
		author = "David Bernal"
		description = "Detects hidden iframes"
		attack = "ATTACK T1189 Drive-by-download"
		date = "2023-11-03"
	strings:
		$hidden1 = "width=0 height=0"
		$hidden2 = "width=0 height=1"
		$hidden3 = "width=1 height=0"
		$hidden4 = "width=1 height=1"
		$hidden5 = "width=100% height=0"
		$hidden6 = "width=100% height=1"
		$hidden7 = "width:100%;\" hidden"
		$hidden8 = "hidden=\"hidden\""

		$iframe = "<iframe src="
	condition:
		filesize < 3MB and

		$iframe and 1 of ($hidden*)
}