param
(
    [array[]]$dir
)
 
function Deny-Delete ($dir)
{
    Foreach ($d in $dir)
    {
        # Copy ACL into New ACL object
        $acl = Get-ACL $d
 
        # Create new access rules
        $ar = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', 'Delete', 'ContainerInherit,ObjectInherit', 'None', 'Deny')
        $ar2 = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', 'DeleteSubdirectoriesAndFiles', 'ContainerInherit,ObjectInherit', 'None', 'Deny')
 
        # Add access rules to new ACL
        $acl.AddAccessRule($ar)
        $acl.AddAccessRule($ar2)
 
        # Apply new ACL to directory
        Set-ACL $d $acl
        Write-Host "[+] " -Fore Green -NoNewLine; Write-Host "Deny-Delete ACL rules were applied to $d" 
    }
}
Deny-Delete -dir $dir