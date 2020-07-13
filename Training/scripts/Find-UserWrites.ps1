Param([string]$dir)

function Find-UserWrites{
    $objs = ls $dir | select -exp fullname    
    foreach ($obj in $objs) {        
        try {$acls = Get-Acl $obj | select -exp access} catch {continue} 
        foreach ($acl in $acls){
            if (($acl.IdentityReference -eq 'NT AUTHORITY\Authenticated Users') -or ($acl.IdentityReference -eq 'BUILTIN\Users')){
                if (($acl.FileSystemRights -match 'CreateFiles') -or ($acl.FileSystemRights -match 'Write')){
                    if (($acl.FileSystemRights -match 'ReadAndExecute') -or ($acl.FileSystemRights -match 'ExecuteFile')){
                        Write-Host -Fore Green $obj -Nonewline; Write-Host " may be writable & executable by non-priv users"
                    }
                }
            }
        }
    }
}
Find-UserWrites $dir
