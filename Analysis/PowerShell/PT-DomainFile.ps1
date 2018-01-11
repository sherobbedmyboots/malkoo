Param ($File)
 
Function PT-Domain-File ( $File )
{
    $USERNAME = "<username>"
    $KEY = "<api-key>"
    $pair = "${USERNAME}:${KEY}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ Authorization = $basicAuthValue;
                  ContentType  = "application/json"
                }
   
    $a = @()
 
    gc $File | foreach{       
        $uristring = "http://api.passivetotal.org/v2/whois?query=$_"
        $data = irm -uri $uristring -method GET -headers $headers
        $a += New-Object -TypeName psobject -Property @{DomainName=$data.domain; Registrar=$data.registrar; CreationDate=$data.registered; Phone=$data.registrant.telephone; Email=$data.registrant.email; `
        Updated=$data.registryUpdatedAt; WhoisServer=$data.whoisServer; Street=$data.registrant.street;City=$data.registrant.city; State=$data.registrant.state;}
        }
$a | select DomainName,Registrar,CreationDate,Phone,WhoisServer,Street,City,State | ft -auto
}
PT-Domain-File -File $File