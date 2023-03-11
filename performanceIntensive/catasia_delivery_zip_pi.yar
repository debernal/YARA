rule Catasia_delivery_zipfile
{
    meta:
		author = "David Bernal"
		description = "Detects zip file used to deliver Catasia executables"
		hash0 = "557d6da8ff2bdb79c0035ec6717d77a83bf31961"
		hash1 = "12c08fcfb8610b2e90d9497d8197828b6ac25bde"
		reference = "https://blog.scilabs.mx/threat-analysis-catasia/"
		version = "2"
    strings:
		$zip_file = { 50 4b 03 04 }
		$ext_exe = ".exe" nocase
		$re1 = / (0?[1-9]|[12][0-9]|3[01])-(0?[1-9]|1[012])-\d{4}\./
    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and

        // contains exactly two zip files
        #zip_file == 2 and

        //file size
        filesize > 100KB and filesize < 600KB and

        // second zip file contains a filename that includes ".exe".
        $ext_exe in (@zip_file[2]+31..@zip_file[2]+100) and

        // second zip file contains a filename that includes the date in dd-mm-yyyy format
        $re1 in (@zip_file[2]+31..@zip_file[2]+100)
}