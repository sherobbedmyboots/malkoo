<# From PSHunt ---- https://github.com/Infocyte/PSHunt/blob/master/Surveys/Survey.ps1


See processes using the network

	$n | select ProcessID,ProcessName,Src_Address,Src_Port,Dst_Address,Dst_Port,protocol,state | ft 

See processes/ports listening

	$n | ? state -eq Listening | select ProcessID,ProcessName,Src_Address,Src_Port,protocol,state | ft

See established connections

	$n | ? state -eq Established | select ProcessID,ProcessName,Src_Address,Src_Port,Dst_Address,Dst_Port,protocol,state | ft

#>

function Get-Netstat {
	# Write-Verbose "Getting Netstat"
	$netstat = @()
	
	# Run netstat for tcp and udp
	$netstat_tcp = &{netstat -ano -p tcp}  | select -skip 4
	$netstat_udp = &{netstat -ano -p udp} | select -skip 4
	
	# Process output into objects
	foreach ($line in $netstat_tcp) { 	
		$val = -Split $line
		$l = $val[1] -Split ":" 
		$r = $val[2] -Split ":" 		
		$netstat += new-Object PSObject -Property @{
			Protocol		= $val[0] 
			Src_Address		= $l[0]
			Src_Port 		= [int]$l[1]
			Dst_Address 	= $r[0] 
			Dst_Port 		= [int]$r[1] 
			State 			= $val[3] 
			ProcessId 		= [int]$val[4]
			ProcessName 	= [String](Get-Process 2>$null -Id ([int]$val[4])).Name
		}			
	}
	foreach ($line in $netstat_udp) { 	
		$val = -Split $line
		$l = $val[1] -Split ":" 
		$netstat += new-Object PSObject -Property @{
			Protocol		= $val[0] 
			Src_Address		= $l[0]
			Src_Port 		= [int]$l[1]
			Dst_Address 	= $null
			Dst_Port 		= [int]$null 
			State 			= $null
			ProcessId 		= [int]$val[3]
			ProcessName 	= [String](Get-Process -Id ([int]$val[3])).Name
		}
	}
	return $netstat
}

Get-Netstat