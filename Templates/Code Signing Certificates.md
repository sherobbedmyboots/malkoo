# Code Signing Certificates
 
Code signing helps determine if software can be trusted by confirming
the identity of the software publisher and guaranteeing that the file
hasn't been altered or corrupted.
 
It does this using two major components:
 
| | |
|-|-|
|[Hash](#hash)|used to verify the file's integrity|
|[Digital Signature](#digital-signature)|used to verify the publisher's identity|
 
 
## Hash
 
When a file is modified, its hash changes:
 
![](images/Code%20Signing%20Certificates/image001.png)
 
 
When a software publisher distributes a file, the hash of the file is
used to guarantee the file has not been modified.
 
In this case, the hash of my original file is:            
 
`A9503EF354A74CE45055C22F2254442216B711D8`
 
If someone downloads `testfile.txt` from the Internet, if it doesn't
have this SHA1 hash it has been modified.  
 
 
## Digital Signature
 
A digital signature uses public key (asymmetric) cryptography to prove
an identity.
 
I can right click --> Digitally Sign File and I will be prompted to enter
my PIN:
 
![](images/Code%20Signing%20Certificates/image002.png)
 
 
Once I've signed it, a new file is created, `Testfile.txt.p7m`, which
shows the contents of the file were signed with my certificate.
 
The file is valid (has not expired) and trusted (was issued by a trusted
third party):
 
![](images/Code%20Signing%20Certificates/image003.png)
 
 
My certificate is trusted because all certificates on my Certification
Path are trusted:
 
![](images/Code%20Signing%20Certificates/image004.png)
 
 
So if you wanted to verify a file came from me and had not been changed,
you'd want the original hash value and my digital signature.
 
That is similar to how code signing works.
 
 
## Code Signing Certificates
 
A valid, trusted code signing certificate confirms authenticity (it's
the actual file they want to distribute) and origin (it came from the
publisher it says it came from).
 
For example, let's use the file winrar-x64-55b6.exe downloaded from the
Internet:
 
![](images/Code%20Signing%20Certificates/image005.png)
 
 
### Signing Process
 
Here is the code signing process for this file:
 
#### 1. Publisher creates a public/private key pair
 
The private key is kept secret and only WinRar has access to it.  This way if something is signed with WinRar's private key, you can trust that it came from WinRar.
 
#### 2. Publisher purchases a digital certificate using the public key
 
The Certificate Authority (CA), in this case Symantec, sells a code signing certificate to WinRar and performs a series of checks to confirm their identity.  Once WinRar passes all checks, Symantec issues them a code signing certificate and binds their public key to it.  This certificate can be revoked at any time if WinRar violates legal terms or reports that the private key has been compromised.
 
#### 3. File is hashed
 
The WinRar file is hashed which creates the hash value `EAB0EFCE044415415A5E1760D5CFA253997C6B7E`. 
 
#### 4. Hash is signed with publisher's private key
 
WinRar signs the hash with their private key.  Now anyone who trusts Symantec also trusts that WinRar is really WinRar and the file hash signed by them is the correct file hash for their program.
 
#### 5. Bundle associated with file
 
The original file, signed hash, and code signing certificate are bundled together and embedded in the file or placed in a separate file. The digital certificate and hash are included with the file so it can be used to verify the publisher's identity and the file's integrity.
 
 
### Verifying Process
 
To verify:
 
#### 1. The end user obtains the file hash of the file
 
This produces the actual hash of the file that was downloaded
 
#### 2. Code signing certificate is checked]
 
The certificate is checked to ensure it's valid (trusted CA, expiry date, revocation list). If the CA (Symantec) is trusted and WinRar's certificate is not
expired or revoked, you can trust that the file was signed by WinRar.
 
#### 3. Public key applied to signed hash
 
The end user extracts WinRar's public key and applies it to the signed hash. This produces WinRar's original hash of the file.
 
#### 4. Original and actual hashes compared
 
The end user compares WinRar's original hash with the actual hash of the file that was downloaded. If the hashes match, then the end user has the exact same file that WinRar created.
 
 
You can see the signing chain using Sysinternals tool "sigcheck":
 
`sigcheck -i winrar-x64-55b6.exe`
 
This shows win.rar GmbH's certificate was issued by COMODO RSA Code
Signing CA which in turn was issued by COMODO RSA Certification
Authority:
 
![](images/Code%20Signing%20Certificates/image006.png)
 
 
So the hash and certificate are valid which means that Windows trusts
that the software downloaded is the exact software the publisher
created. 
 
Now, what happens on 6/2/2020 when the code signing certificate
expires?  Or WinRar gets their private key stolen in 2018 and their
certificate must be revoked? 
 
If the certificate is revoked or expired, the software will no longer be
trusted by Windows... but you verified in August 2017 that it
**_was_** the actual software you wanted and still wish to run
it. 
 
To fix this issue, there are time-stamping certificates and CAs.
 
 
## Time-Stamping Certificates
 
The code signing certificate just confirms that the code was signed.  A
time-stamping certificate confirms the time of **_when_** the
code was signed. 
 
This allows the code to be trusted after the code signing certificate
expires.
 
If the code signing certificate is ever revoked, it will be revoked on
and after a specific date.  By validating a timestamp, code signatures
issued before the revocation date will remain valid.
 
### Signing Process
 
1. WinRar sends the file's hash value to the Time Stamping Authority (TSA)
 
2. The TSA concatenates a timestamp to this hash and calculates a new hash
 
3. The TSA signs this "new" hash with its private key
 
4. The timestamp and the signed hash are sent back to WinRar who stores them in the file
 
### Verifying Process
 
1. End user verifies the TSA's public key is still valid (expiry date, revocation list, trusted root cert)
 
2. End user then applies TSA's public key to the signed hash provided by TSA creating what should be TSA's "new" hash
 
3. The end user concatenates the timestamp provided by TSA with the actual file hash and calculates what also should be TSA's "new" hash
 
4. If the two hashes match, then the end user has the same file whose hash was timestamped by the TSA
 
Now let's look at the Time-Stamping Certificates:
 
![](images/Code%20Signing%20Certificates/image007.png)
 
 
## Summary
 
Code signing does not tell you whether the file is malicious or not, it
only confirms the identity of the publisher and if the code has been
modified.
 
- Digitally signed code is backed by a certificate issued by a trusted
    third party (CA)
 
- Unsigned code may include publisher data but if it doesn't provide
    any **_evidence of origin or file integrity_**, we cannot
    trust that it is what it says it is
 
Time-stamp signing allows code to be trusted after a private key is
compromised or the certificate is revoked.  It proves the certificate
was valid and trusted at the time of the timestamp.
 