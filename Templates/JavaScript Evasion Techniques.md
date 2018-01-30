# JavaScript Evasion Techniques

New techniques created, old ones modified, combinations used together

Changed to work in specific environments, evade certain detection tools

Most require manual analysis


- [Encoding](#encoding)








## Encoding

- base64
- url, double url
- hex
- unicode 
- non-alphanumeric (JJencode, AAencode)
- whitespace


avoids searches for keywords, patterns, regex-based filters


## Obfuscation

- random variables and methods
- different object notations (dot and bracket)
- pulling info from different contexts (JS can access DOM, PDFs, Flash, Java, etc.)
- callee property


## Time Checks

- SetTimeout()
- SetInterval()




## Packing

- reducing unnecessary variables
- shortening variable names
- Dean Edwards Packer

## Chaining Together
