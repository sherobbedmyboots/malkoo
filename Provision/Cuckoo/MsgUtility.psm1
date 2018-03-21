function Expand-MsgAttachment
{
    [CmdletBinding()]

    Param
    (
        [Parameter(ParameterSetName="Path", Position=0, Mandatory=$True)]
        [String]$Path,

        [Parameter(ParameterSetName="LiteralPath", Mandatory=$True)]
        [String]$LiteralPath,

        [Parameter(ParameterSetName="FileInfo", Mandatory=$True, ValueFromPipeline=$True)]
        [System.IO.FileInfo]$Item
    )

    Begin
    {
        # Load application
        Write-Verbose "Loading Microsoft Outlook..."
        $outlook = New-Object -ComObject Outlook.Application
        if (Test-Path Out) {
            Remove-Item -Recurse -Force Out | Out-Null
        }
        New-Item -ItemType 'Directory' -Path Out -Force | Out-Null
    }

    Process
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Path"        { $files = Get-ChildItem -Path $Path }
            "LiteralPath" { $files = Get-ChildItem -LiteralPath $LiteralPath }
            "FileInfo"    { $files = $Item }
        }

        $files | % {
            # Work out file names
            $msgFn = $_.FullName

            # Skip non-.msg files
            if ($msgFn -notlike "*.msg") {
                Write-Verbose "Skipping $_ (not an .msg file)..."
                return
            }

            # Extract message body
            Write-Verbose "Extracting attachments from $_..."
            $msg = $outlook.CreateItemFromTemplate($msgFn)
            $msg.Attachments | % {
                # Work out attachment file name
                $attFn = $msgFn -replace '\.msg$', " - Attachment - $($_.FileName)"

                # Do not try to overwrite existing files
                if (Test-Path -literalPath $attFn) {
                    Write-Verbose "Skipping $($_.FileName) (file already exists)..."
                    return
                }

                # Save attachment
                Write-Verbose "Saving $($_.FileName)..."
                $_.SaveAsFile($attFn)
                
                # Output to pipeline
                mv $attFn 'Out\'
            }
        }
    }

    End
    {
        Write-Verbose "Done."
    }
}
