@echo off
REM Qui la versione 16-bit FUNZIONA!
echo Creazione dell'eseguibile DOS 16-bit ZSPAN.EXE...
dmc -o+all -mld -DTBAR -DDOS_16 -DBLOCKED_IO -DHANDLE_COMMENT ZSpan.c
