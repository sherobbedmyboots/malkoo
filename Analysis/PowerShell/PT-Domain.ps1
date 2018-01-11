Param ($Domain)
 
Function PT-Domain ( $Domain )
{
    $USERNAME = "<username>"
    $KEY = "<api-key>"
    $pair = "${USERNAME}:${KEY}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $uristring = "http://api.passivetotal.org/v2/dns/passive?query=$Domain"
    $headers = @{ Authorization = $basicAuthValue;
                  ContentType  = "application/json"
                }
           
    $data = irm -uri $uristring -method GET -headers $headers
    $data.results
}
PT-Domain -Domain $Domain
 
 
 
 
