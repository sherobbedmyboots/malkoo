# tshark -r .\c2-pcap.pcapng -2 -R "ssl.handshake.certificates" -T pdml > ssl.xml
#
# Get-PcapCertInfo.ps1 ssl.xml
#

Param
(
    [string]$file
)

[xml]$xml = gc $file

$packet = $xml.pdml.packet

foreach ($p in $packet){
    
    # Find number of certificates in each packet
    $count = ($p.proto[6].field.field[3].field[3].field | measure).count
    
    for ($i=1; $i -lt $count; $i+2){
        
        # Grab each certificate        
        $cert = $p.proto[6].field.field[3].field[3].field[$i]
        
        $a = @()
        foreach ($c in $cert){

            # subject
            if($subjectCN = $c.field[0].field.field.field[12].field.field[1].field.show){
                $subjectO  = $c.field[0].field.field.field[11].field.field[1].field.show
                $subjectL  = $c.field[0].field.field.field[10].field.field[1].field.show
                $subjectS  = $c.field[0].field.field.field[9].field.field[1].field.show
                $subjectC  = $c.field[0].field.field.field[8].field.field[1].show
            }
            elseif($subjectCN = $c.field[0].field.field.field[11].field.field[1].field.show){
                $subjectO  = $c.field[0].field.field.field[10].field.field[1].field.show
                $subjectL  = $c.field[0].field.field.field[9].field.field[1].field.show
                $subjectS  = $c.field[0].field.field.field[8].field.field[1].field.show
                $subjectC  = $c.field[0].field.field.field[7].field.field[1].show
            }
            elseif($subjectCN = $c.field[0].field.field.field[10].field.field[1].field.show){
                $subjectO  = $c.field[0].field.field.field[9].field.field[1].field.show
                $subjectL  = $c.field[0].field.field.field[8].field.field[1].field.show
                $subjectS  = $c.field[0].field.field.field[7].field.field[1].field.show
                $subjectC  = $c.field[0].field.field.field[7].field.field[1].show
            }
            $subjectCN = $c.field[0].field.field.field[11].field.field[1].field.show
            $subjectO  = $c.field[0].field.field.field[10].field.field[1].field.show
            $subjectL  = $c.field[0].field.field.field[9].field.field[1].field.show
            $subjectS  = $c.field[0].field.field.field[8].field.field[1].field.show
            $subjectC  = $c.field[0].field.field.field[7].field.field[1].show
            
            # valid
            $notAfter  = $c.field[0].field.field.field[6].show
            $notBefore = $c.field[0].field.field.field[5].show
                       
            # issuer
            if($issuerCN  = $c.field[0].field.field.field[5].field.field[1].field.show){
                $issuerOU  = $c.field[0].field.field.field[4].field.field[1].field.show
                $issuerO   = $c.field[0].field.field.field[2].field.field[1].field.show
                $issuerC   = $c.field[0].field.field.field[1].field.field[1].field.show
            }
            else{
                $issuerCN  = $c.field[0].field.field.field[4].field.field[1].field.show
                $issuerOU  = $c.field[0].field.field.field[3].field.field[1].field.show
                $issuerO   = $c.field[0].field.field.field[2].field.field[1].field.show
                $issuerC   = $c.field[0].field.field.field[1].field.field[1].show
            }

            $a += New-Object -TypeName psobject -Property @{
                SubjectCN = $subjectCN;
                SubjectO  = $subjectO;
                SubjectL  = $subjectL;
                SubjectS  = $subjectS;
                SubjectC  = $subjectC;
                NotAfter  = $notAfter;
                NotBefore = $notBefore;
                IssuerCN  = $issuerCN;
                IssuerOU  = $issuerOU;
                IssuerC   = $issuerC;
            }
        }
    }
}
$a