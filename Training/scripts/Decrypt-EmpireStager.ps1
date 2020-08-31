<# 

.DESCRIPTION
    Decrypts Empire Stager with staging key

.EXAMPLE
    .\Decrypt-EmpireStager -stager 'c:\stager.txt' -key 'sxU7JxW!}t5rdcb;Ktjl6'

.NOTES
    If an Empire launcher is captured, it will contain the staging key and the URI of the stager.  
    If the stager is obtained, this script will decrypt the stager.
    This script assumes you save the stager as a text file.      

#>



Param
( 
    [string] $stager,
    [string] $key 
)



function Decrypt-EmpireStager ( $stager, $key )
{
    # Read in the stager in bytes
        
    $data=$(gc $stager -encoding byte)
            
    # Convert key to bytes

    $K=[SysTem.TexT.ENCODiNg]::ASCII.GeTBYteS($key)
    
    # Perform XOR
    
    $R={$D,$K=$ArGs;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.COUnT])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bXOR$S[($S[$I]+$S[$H])%256]}};
       
    # Extract first four lines of stager

    $iv=$dAta[0..3];
    
    # Rest of stager

    $DaTa=$DaTA[4..$DatA.leNgTh]
    
    # Combine and convert to ASCII

    $result = $(-joIn[ChAR[]](& $R $datA ($IV+$K)))
    
    $result 
        
}
Decrypt-EmpireStager -stager $stager -key $key