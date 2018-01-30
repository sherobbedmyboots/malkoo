# Verifying Digital Signatures of PE Files

On Windows 7 and later versions, all native portable executable (PE)
files, including EXEs and DLLs, that are running in processes, device
drivers, and services should be signed by Microsoft.

A file signed with a valid, trusted certificate confirms
**authenticity** and **origin**---Microsoft signs a
file to prove it is authentic and Microsoft should be the only one that
could have signed it with their private key.

Many of the alerts we see involve a file that appears to be a legitimate
OS binary.  In this case one of the first things we need to do is
verify the PE file's signature.

PE files are signed in one of two ways:

- [Embedded](#embedded-signature-files) - A digital signature (Microsoft
    uses Authenticode) is embedded inside the PE

- [Catalog](#catalog-signed-files) - A hash of the PE can be
    found in a security catalog (`.CAT`) file

## Embedded-Signature Files

Embedded signatures are placed at the end of the signed file and several
different tools can be used to find it, parse it, and verify it.

Take `consent.exe` for example:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image001.png)


![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image002.png)


`Get-AuthenticodeSignature` shows the signature type is Authenticode:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image003.png)


## Catalog-Signed Files

Catalog-signed files do not have an embedded digital signature so they
will not have a digital signature properties tab or pass a
`Get-AuthenticodeSignature` check (on Windows 7). 

Verifying them on Windows 7 hosts requires a tool such as SysInternal's
Sigcheck which looks up the Authenticode hash of the file in its
associated catalog file and verifies the signature of the catalog file.

Let's use `sethc.exe` for example.

Using `Get-AuthenticodeSignature` on a Windows 7 host shows it as
unsigned because the file doesn't contain an embedded digital signature:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image004.png)


But SigCheck shows that it is signed by Microsoft:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image005.png)


Let's walk through how it does this...

Using Sigcheck's `-i` switch will show complete signer and countersigner
information as well as the catalog file that contains the file's
Authenticode hash:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image006.png)


Sigcheck has already done this, but we can verify the signature of the
catalog file and see that it is valid:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image007.png)


So if the PE Authenticode hash is inside the catalog file, this proves
the PE was signed by Microsoft.

You can verify this by using the `-h` switch to show the Authenticode
Hashes of the PE file:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image008.png)


Browsing to the `.CAT` file and double-clicking it will show you all the
Authenticode hashes it contains.

We can see it contains the PESHA1 hash for `sethc.exe`:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image009.png)


So the `.CAT` file contains the Authenticode hash of the PE file and also
has a valid digital signature.  This confirms the PE file's authenticity
and origin.

This is all done in one command using the SigCheck tool:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image005.png)


On Windows 10 machines, `Get-AuthenticodeSignature` will also verify
catalog-signed PE files:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image010.png)


It also contains a property that identifies it as a catalog-signed file:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image011.png)


## Checking a File's Signature

Checking the signature of both catalog-signed or embedded-signature PE
files on a remote Windows 10 host can be performed with one command:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image012.png)


![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image013.png)


But checking a catalog-signed file on a Windows 7 host will not work
with this command:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image014.png)


The
[Check-FileSignature.ps1]() script checks for the OS version of a host, then:

- If Windows 10, verifies file's signature with the
    `Get-AuthenticodeSignature` cmdlet

- If not Windows 10, uses an embedded copy of `sigcheck.exe` to verify
    the file's signature

So running it remotely on a Windows 10 host shows the output from the
`Get-AuthenticodeSignature` cmdlet:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image015.png)


And running it on a Windows 7 host shows the output from Sysinternal's
SigCheck tool:

![](images/Verifying%20Digital%20Signatures%20of%20PE%20Files/image016.png)


This provides a quick and easy way to check if a file is signed when
given a remote host and the file's full path.
