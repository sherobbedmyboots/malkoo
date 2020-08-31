<#
.DESCRIPTION
    Adds user to an ACL of a folder and all folders/subfolders/files it contains

.EXAMPLE
    Add-UserToACL -user 'userone' -server 'localhost' -path 'd$\path\to\folder' -access FullControl
    
#>


param
(            
 [Parameter(Mandatory=$true)][string[]]$User,
 [Parameter(Mandatory=$true)][string]$Server,
 [Parameter(Mandatory=$true)][string]$Path,
 [Parameter(Mandatory=$true)][string]$Access              
)   


function Add-UserToACL 
{   
       
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Testing folder path..."
    
    $fullpath = '\\' + $Server + '\' + $Path
        
    if (!(Test-Path $fullpath)) 
    {
        Write-Host -ForegroundColor Red [+] (get-date -UFormat "%H:%M:%S") "   Path to $Path not found... Exiting!" 
        Exit
    }
                     
    Write-Host -ForegroundColor Cyan [+] (get-date -UFormat "%H:%M:%S") "   Adding user $User to folder permissions..."
    $rule=new-object System.Security.AccessControl.FileSystemAccessRule ($User,$Access,"Allow")
    $acl = Get-ACL -Path $fullpath -ErrorAction stop                
    $acl.SetAccessRule($rule)                
    gci $fullpath -recurse -fo | Set-ACL -ACLObject $acl -ErrorAction stop                
    Write-Host -ForegroundColor Green [+] (get-date -UFormat "%H:%M:%S") "   Successfully set permissions for $User on $fullpath"            
}
Add-UserToACL -user $User -server $Server -path $Path -access $Access
