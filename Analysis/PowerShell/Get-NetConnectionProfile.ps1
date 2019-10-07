
function Get-NetConnectionProfile
{
    $NLMType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
    $NetworkListManager = [Activator]::CreateInstance($NLMType)
    $Categories = @{
        0 = 'Public'
        1 = 'Private'
        2 = 'Domain'
    }
    $Networks = $NetworkListManager.GetNetworks(1)
   
    $a = @()
    foreach ($Network in $Networks)
    {
        $ifaces = gwmi win32_NetworkAdapterConfiguration | ? DefaultIPGateway -ne $null | select *
 
        if ($Network.GetName() -in $ifaces.DNSDomainSuffixSearchOrder){
            $ipaddress = $ifaces.ipaddress[0]
        }
        else{
            $ipaddress = ($ifaces | ? DNSDomain -eq $null).IPaddress[0]
        }
        $a += New-Object -TypeName psobject -Property @{
            Name = $Network.GetName()
            Category = $Categories[($Network.GetCategory())]
            IPAddress = $ipaddress
            IsConnected = $Network.IsConnected
            IsConnectedToInternet = $Network.IsConnectedToInternet
        }
    }
    $a | select Name,Category,IPAddress,IsConnected,IsConnectedToInternet | ft -auto
   
}
Get-NetConnectionProfile