rule Catasia_delivery_zipfile
{
    meta:
        author = "David Bernal"
        description = "Detects zip file used to deliver Catasia executables"
        hash0 = "557d6da8ff2bdb79c0035ec6717d77a83bf31961"
        hash1 = "12c08fcfb8610b2e90d9497d8197828b6ac25bde"

    strings:
        $zip_file = { 50 4b 03 04 }
        $ext_exe = ".exe" nocase

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and

        // contains exactly two zip files
        #local_file == 2 and

        //file size
        filesize > 100KB and filesize < 600KB and

        // second zip file contains a filename that includes ".exe".
        $ext_exe in (@zip_file[2]+31..@zip_file[2]+100)
}