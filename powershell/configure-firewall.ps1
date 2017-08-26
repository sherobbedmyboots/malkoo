# Configure firewall

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True


Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow –NotifyOnListen True -AllowUnicastResponseToMulticast True –LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log


# Find a rule:

Get-NetFirewallRule | Where-Object { $_.Name -like '*FPS*' } | Select-Object Name,Enabled,Direction



# Open up SMB port 445:

Set-NetFirewallRule -Name 'FPS-SMB-In-TCP' -Enabled True


# Do the rest at:

# https://docs.microsoft.com/en-us/windows/access-protection/windows-firewall/windows-firewall-with-advanced-security-administration-with-windows-powershell

