rule PowershellHiddenWindowParameters
{
        meta:
                author = "David Bernal"
                description = "Detects PowerShell Hidden Windows Parameters. ATT&CK Defense Evasion, sub-technique of T1564, ID T1564.003"
        strings:
                $powershell = "powershell" nocase
                $re = /(\/|\-)(w|wi|win|wind|windo|window|windows|windowst|windowsty|windowstyle)\s+(1|h|hi|hid|hidd|hidde|hidden)\s/ nocase
        condition:
                all of them
}