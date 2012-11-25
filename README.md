ZTools
======
 
Here there are two tiny C utilities to split ZIP archives like WinZip/PKZip (ZSplit) and 
to encrypt a ZIP archive with AES (ZAes).
 
ZSpan
=====
 
Simply compile and do:
 
  ZSpan <source.zip> <KiB segment> <destination radix>


ZAes
====

To compile the utility it is necessary to download elsewhere from the Internet the
Dr. B. Gladman HMAC code or the openssl library, and the libtomcrypt (AES and SHA-1
code).

 *The code is given to Public Domain.*
