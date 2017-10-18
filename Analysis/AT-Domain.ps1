Param ($indicator)
 
Function AT-Domain ( $indicator)
{
    $USERNAME = "7907130239a84e1ba0f02421c6bd2948e7f10ef43da8428cbdb0c8ec9899edfc"
    $KEY = ""
    $pair = "${USERNAME}:${KEY}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"
    $headers = @{ Authorization = $basicAuthValue;
                  ContentType  = "application/json"
                }
    $firstpart = "https://platform.activetrust.net:8000/api/services/intel/lookup/indicator/host?value="
    $secondpart = "&source=isight&wait=true"
    $uristring = $firstpart + $indicator + $secondpart
    $data = irm -uri $uristring -method GET -headers $headers
    $data

}
AT-Domain -indicator $indicator