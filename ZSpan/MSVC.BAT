@set OPT=/G5f /MD /O1g
@rem @set OPT=/ZI /MDd
cl /nologo %OPT% /DTBAR /DBLOCKED_IO /DHANDLE_COMMENT ZSpan.c /link /opt:nowin98
