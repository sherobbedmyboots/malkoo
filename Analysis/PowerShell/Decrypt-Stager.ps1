<#
.DESCRIPTION
    Decrypts Stager with staging key
.EXAMPLE
    .\Decrypt-Stager -stager 'c:\stager.txt' -key 'sxU7JxW!}t5rdcb;Ktjl6'
.NOTES
    If a launcher with staging key is captured, obtain and decrypt the stager    
#>
Param
(
    [string] $stager,
    [string] $key
)
function Decrypt-Stager ( $stager, $key )
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
Decrypt-Stager -stager $stager -key $key