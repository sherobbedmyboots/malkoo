Param ($urlfile)
 
Function Search-SafeBrowse ( $urlfile )
{
    $APIKEY = "<API KEY>"
    $uristring = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$APIKEY"
    gc .\sites.txt | %{$urls +="{`"url`": `"$_`"},"}
    #write-host $url
    $json = @"
    {
        "client": {
            "clientId": "<client id>",
            "clientVersion": "1"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                $urls
                {"url": "https://www.sans.org"}
            ]
        }
    }
"@ 
            
     $data = Invoke-RestMethod -uri $uristring -Method POST -Body $json -ContentType 'application/json'
     $data.matches | select threat,threatType,platformType,threatEntryType | ft -auto
}
Search-SafeBrowse -urlfile $urlfile