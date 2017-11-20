Param
(
    [string]$dir
)

function Find-UserWrites
{
    $objs = ls $dir| select -exp fullname
    $acls = @()

    foreach ($obj in $objs) {
        
        $hit = (Get-ACL $obj).Access | ?{($_.IdentityReference -eq 'NT AUTHORITY\Authenticated Users') -or `
                                         ($_.IdentityReference -eq 'BUILTIN\Users')}
        if ($hit){                                 
            
            $match = (Get-ACL $obj).Access | ? {($_.FileSystemRights -match 'CreateFiles') -or `
                                                ($_.FileSystemRights -match 'Write')}
            
            if ($match){
                Write-Host -Fore Green $obj -Nonewline; Write-Host " can be written to by Users"
            }
        }
    }
}
Find-UserWrites -dir $dir