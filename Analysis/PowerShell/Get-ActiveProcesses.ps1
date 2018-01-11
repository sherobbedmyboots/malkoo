<# From PSHunt ---- https://github.com/Infocyte/PSHunt/blob/master/Surveys/Survey.ps1

Example

	$p = Invoke-Command -ComputerName <hostname> -FilePath .\Get-ActiveProcesses.ps1 -Credential $cred


See recently started processes

	$p | select CreationDate,Name,ProcessID,Owner,PathName | sort -desc CreationDate | ft -auto

See unsigned binaries

	$p | % {if($_.PathName){Get-AuthenticodeSignature $_.PathName}} | ? Status -ne Valid | select -exp Path

See binaries running out of non-standard paths

	$p | %{if($_.PathName){$_ | ? PathName -notmatch 'System32|Program Files|SysWOW64'}} | select Name,ParentProcessName,Owner,PathName | ft -auto


#>

function Get-Processes {
	# Write-Verbose "Getting ProcessList"
	# Get Processes 
	$processes = Get-WmiObject -Class Win32_Process
	
	$processList = @()	
	foreach ($process in $processes) {

		try {
			$Owner = $process.GetOwner().Domain.ToString() + "\"+ $process.GetOwner().User.ToString()
            $OwnerSID = $process.GetOwnerSid().Sid
            $CreationDate = $process.ConvertToDateTime($process.CreationDate) 
		} catch {
			# Write-Warning "Owner could not be determined for $($process.Caption) (PID $($process.ProcessId))" 
		}
		
        $thisProcess = New-Object PSObject -Property @{
			ProcessId			= [int]$process.ProcessId
			ParentProcessId		= [int]$process.ParentProcessId
			ParentProcessName 	= ($processes | where { $_.ProcessID -eq $process.ParentProcessId}).Caption
			SessionId			= [int]$process.SessionId
			Name				= $process.Caption
			Owner 				= $Owner
            OwnerSID            = $OwnerSID 
			PathName			= $process.ExecutablePath
			CommandLine			= $process.CommandLine
			CreationDate 		= $CreationDate
			ModuleList 			= @()
		}
		<#
		if ($process.ExecutablePath) {
			# Get hashes and verify Signatures with Sigcheck
			$Signature = Invoke-Sigcheck $process.ExecutablePath -GetHashes | Select -ExcludeProperty Path
			$Signature.PSObject.Properties | Foreach-Object {
				$thisProcess | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -Force
			}
		}#>
		
		$processList += $thisProcess 
	}
	return $processList
}

Get-Processes




