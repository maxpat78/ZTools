cl test.c sha1.o tomcrypt.lib /link /opt:nowin98 /fixed:no /map /out:testO.exe
cl test.c tomcrypt.lib /link /opt:nowin98 /fixed:no /map
