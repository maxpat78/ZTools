/* TODO:
 prevedere che EDIR e/o commento sforino l'ultimo segmento!
 
 gestire il caso "bit 3" (=data block dopo i dati compressi)? */

/* NOTA: la barra di avanzamento tiene conto del NUMERO dei file, non della
dimensione n‚ di quella della Central Directrory... */

/* BUG! La versione 16-bit WATCOM continua a dare problemi con -DBLOCKED_IO:
apparentemente, non Š un problema di riallocazione della memoria! */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>

#ifdef TBAR
#include "tbar.c"
#endif

#define Z_ERROR(x) fatal_error(x)

/* 32-bit types */
#ifndef DOS_16
 typedef unsigned int DWORD;
 typedef unsigned short WORD;
#else
 typedef unsigned long DWORD;
 typedef unsigned int WORD;
#endif

/* Con Visual C++ 32-bit queste strutture devono essere allineate al byte... */
#pragma pack(1)
/*
      Central File header:

        central file header signature   4 bytes  (0x02014b50)
        version made by                 2 bytes
        version needed to extract       2 bytes
        general purpose bit flag        2 bytes
        compression method              2 bytes
        last mod file time              2 bytes
        last mod file date              2 bytes
        crc-32                          4 bytes
        compressed size                 4 bytes
        uncompressed size               4 bytes
        filename length                 2 bytes
        extra field length              2 bytes
        file comment length             2 bytes
        disk number start               2 bytes
        internal file attributes        2 bytes
        external file attributes        4 bytes
        relative offset of local header 4 bytes

        filename (variable size)
        extra field (variable size)
        file comment (variable size)
*/
typedef struct _CENT
{
	DWORD Sig;
	WORD MadeBy;
	WORD ToExtract;
	WORD Flag;
	WORD CompMethod;
	WORD FileTime;
	WORD FileDate;
	DWORD Crc32;
	DWORD CompSize;
	DWORD Size;
	WORD NameLen;
	WORD ExtraLen;
	WORD CommentLen;
	WORD Disk;
	WORD IntAtrr;
	DWORD ExtAttr;
	DWORD Offset;
} CENT;


/*
      End of central dir record:

        end of central dir signature    4 bytes  (0x06054b50)
        number of this disk             2 bytes
        number of the disk with the
        start of the central directory  2 bytes
        total number of entries in
        the central dir on this disk    2 bytes
        total number of entries in
        the central dir                 2 bytes
        size of the central directory   4 bytes
        offset of start of central
        directory with respect to
        the starting disk number        4 bytes
        zipfile comment length          2 bytes
        zipfile comment (variable size)
*/
typedef struct _EDIR
{
	DWORD Sig;
	WORD Disk;
	WORD StartDisk;
	WORD Entries;
	WORD Total;
	DWORD Size;
	DWORD Offset;
	WORD CommentLen;
} EDIR;


/*
    Local file header:

        local file header signature     4 bytes  (0x04034b50)
        version needed to extract       2 bytes
        general purpose bit flag        2 bytes
        compression method              2 bytes
        last mod file time              2 bytes
        last mod file date              2 bytes
        crc-32                          4 bytes
        compressed size                 4 bytes
        uncompressed size               4 bytes
        filename length                 2 bytes
        extra field length              2 bytes

        filename (variable size)
        extra field (variable size)
*/
typedef struct _LENT
{
	DWORD Sig;
	WORD ToExtract;
	WORD Flag;
	WORD CompMethod;
	WORD FileTime;
	WORD FileDate;
	DWORD Crc32;
	DWORD CompSize;
	DWORD Size;
	WORD NameLen;
	WORD ExtraLen;
} LENT;
#pragma pack()

EDIR ed;
FILE *ZIN, *ZOUT;
WORD Disk = 0;
char *CentralDir;

/* Segmento massimo, modello nome destinazione con .zip */
DWORD MaxLen; /* da esprimere in K */
char* Template; /* es. "c:\windows\dest" -> "c:\windows\dest.zip" */


char* strcatwm(char* a, char* b)
{
 char* s = malloc(1+strlen(a)+strlen(b));
 assert(s);
 strcpy(s,a);
 return strcat(s,b);
}


void fatal_error(char* s)
{
 puts(s);
 exit(666);
}


/* fread() e fwrite() assumono size_t, che, con un compilatore 16-bit, ammonta al massimo a 64K...*/
void Z_Read(void *ptr, DWORD n)
{
#ifndef DOS_16
 if ( fread(ptr,1,n,ZIN) != n )
  Z_ERROR("Impossibile leggere i byte richiesti");
#else
 DWORD count=0, c=n;
 while ( c > 0xFFFF )
 {
  count += fread( ptr,1,0xFFFF,ZIN );
  c -= 0xFFFF;
  (char*) ptr += 0xFFFF;
 }
 count += fread( ptr,1,c,ZIN );
 if ( count != n )
  Z_ERROR("Impossibile leggere i byte richiesti");
#endif
}


void Z_Write(void *ptr, DWORD n)
{
#ifndef DOS_16
 if ( fwrite(ptr,1,n,ZOUT) != n )
  Z_ERROR("Impossibile scrivere i byte richiesti");
#else
 DWORD count=0, c=n;
 while ( c > 0xFFFF )
 {
  count += fwrite( ptr,1,0xFFFF,ZOUT );
  c -= 0xFFFF;
  (char*) ptr += 0xFFFF;
 }
 count += fwrite( ptr,1,c,ZOUT );
 if ( count != n )
  Z_ERROR("Impossibile scrivere i byte richiesti");
#endif
}


void GetLE(LENT* le)
{
 Z_Read( le,sizeof(LENT) );
 if (le->Sig != 0x04034B50)
  Z_ERROR("Marcatore locale (0x04034B50) mancante");
}


/* Scrive n byte da ZIN a ZOUT, a piccoli blocchi */
void StepWrite(DWORD n)
{
#ifdef BLOCKED_IO
/* Scrive n byte da ZIN a ZOUT, a piccoli blocchi */
/* Non funziona con WATCOM 16-bit? Colpa di malloc()?? */
#ifndef DOS_16
#define BLOCK 64*1024
#else
#define BLOCK 8*1024
#endif
 char* IoBuF = malloc(BLOCK);
 assert(IoBuF);
 while ( n > BLOCK )
 {
  Z_Read( IoBuF,BLOCK );
  Z_Write( IoBuF,BLOCK );
  n -= BLOCK;
 }
 Z_Read( IoBuF,n );
 Z_Write( IoBuF,n );
 free(IoBuF);
#else
/* Scrive 1 byte alla volta (non spreca buffer, ma LENTO!) */
 char c;
 while (n--)
 {
  Z_Read( &c,1 );
  Z_Write( &c,1 );
 }
#endif
}


/* Apre il prossimo file dello span */
void NextOpen()
{
 char *newname = strcatwm(Template,".zip");

 if (ZOUT)
 {
  char *oldname = strcatwm(Template,".zip");
  sprintf( strstr(oldname,".zip"),".z%02d",Disk );
  fclose( ZOUT );

  if ( rename(newname,oldname) != 0 )
   Z_ERROR("Impossibile rinominare un file necessario");

  free(oldname);
}

 if ( (ZOUT=fopen(newname,"wb")) == 0)
  Z_ERROR("Impossibile aprire il file di destinazione");

 free(newname);
}


void Process()
{
 DWORD n=0, sig = 0x08074B50, scribenda=0, scripta=4;
 CENT* ce = (CENT*) CentralDir;
#ifdef TBAR
 TEXTBAR* b = tbar_init(25);
 b->max = ed.Total;
 puts("ZSpan - creazione di archivi ZIP \"spanned\", (c)2002,2003 A.G.\n");
 printf( "Ripartizione in blocchi di %ld byte...\n",MaxLen );
#endif

 NextOpen();
 Z_Write( &sig,4 );

 while (n++ < ed.Total)
 {
   LENT le;

   /* Assume i dati corretti dalla LE */
   fseek(ZIN,ce->Offset,SEEK_SET);
   GetLE(&le);
   fseek(ZIN,ce->Offset,SEEK_SET);

   scribenda = sizeof(LENT)+le.NameLen+le.ExtraLen;
   if (scripta+scribenda > MaxLen)
   {
    Disk++;
    NextOpen();
    scripta=0;
   }

   ce->Offset = ftell(ZOUT);
   ce->Disk = Disk;

   StepWrite(scribenda);
   scripta += scribenda;

   scribenda = ce->CompSize;
   while ( scripta+scribenda > MaxLen )
   {
    DWORD diff = MaxLen-scripta;
    StepWrite(diff);
    Disk++;
    NextOpen();
    scripta = 0;
    scribenda -= diff;
   }
   StepWrite(scribenda);
   scripta += scribenda;

   (char*) ce = (char*) ce+sizeof(CENT)+ce->NameLen+ce->ExtraLen+ce->CommentLen;
#ifdef TBAR
   tbar_sprintf( b,n );
   printf( "File copiati: %s %ld%% (Disco %d)\r",b->bar,b->pct,Disk+1 );
#endif
 }

/* ATTENZIONE: forse bisognerebbe prevedere che EDIR ed eventuale commento 
vadano su un altro disco... la CDIR dovrebbe fare storia a s‚! */
 if ( ed.Size+scripta+sizeof(EDIR) < MaxLen )
 {
  ed.Offset = ftell(ZOUT);
  Z_Write( CentralDir,ed.Size );
  ed.Disk = Disk;
  ed.StartDisk = Disk;
  Z_Write( &ed,sizeof(EDIR) );
 } else /* Central Directory sparsa */
 {
  DWORD i=0;
  Disk++;
  NextOpen();
  ed.StartDisk = Disk;

  scripta = n = 0;
  ce = (CENT*) CentralDir;

  while (n++ < ed.Total)
  {
   scribenda = sizeof(CENT)+ce->NameLen+ce->ExtraLen;
   if (scripta+scribenda > MaxLen)
   {
    Disk++;
    NextOpen();
    scripta = i = 0;
   }
   Z_Write( ce,scribenda );
   scripta += scribenda;
   i++;
   (char*) ce = (char*) ce+sizeof(CENT)+ce->NameLen+ce->ExtraLen+ce->CommentLen;
  }
  /* Siamo sicuri che la EDIR ci stia tutta...??? */
  ed.Disk = Disk;
  ed.Entries = i;
  ed.Offset = 0;
  Z_Write( &ed,sizeof(EDIR) );
 }

#ifdef HANDLE_COMMENT
 /* ...e, soprattutto, che IL COMMENTO ci stia tutto? */
 /* Da notare che WinZip 8.1 riconosce solo il commento finale all'archivio,
 mentre ignora quelli locali nella CDIR ai singoli file! */
 if (ed.CommentLen)
 {
  fseek(ZIN,-ed.CommentLen,SEEK_END);
  StepWrite(ed.CommentLen);
 }
#endif

 fclose(ZOUT);
 fclose(ZIN);
}


/*
 SINTASSI:
 ========

 file.zip .................. nome dell'archivio da ripartire
 segmento KiByte ........... dimensione di Ki-byte del segmento
 radice .................... radice dei file di destinazione (saranno aggiunte
                             le estensioni .zip o .z<nn>)
*/
int main(int argc,char** argv)
{
 if (argc < 4)
  Z_ERROR("Uso: ZSpan <file.zip> <KiB segmento> <radice>");

 MaxLen = atol(argv[2]) * 1024;
 Template = argv[3];

 if ( (ZIN=fopen(argv[1],"rb")) == 0)
  Z_ERROR("Impossibile aprire il file di origine");

#ifndef DOS_16
 if (MaxLen<1024 || MaxLen>UINT_MAX)
#else
 if (MaxLen<1024 || MaxLen>ULONG_MAX)
#endif
	 Z_ERROR("Dimensione del segmento piuttosto improbabile");

 /* Inutile lavorare... */
 fseek(ZIN,0,SEEK_END);
 if (ftell(ZIN) <= MaxLen)
  Z_ERROR("L'intero archivio misura meno del segmento");

 /* assumiamo uno ZIP senza commento! */
 fseek(ZIN,-22,SEEK_END);
 Z_Read( &ed,sizeof(EDIR) );

 /* Qui prevediamo ANCHE il commento... */
 if (ed.Sig != 0x06054B50)
#ifdef HANDLE_COMMENT
 {
  DWORD i = 65536+sizeof(EDIR);
  EDIR* p;
  (void*) p = (void*) CentralDir = malloc(i);
  assert(p);
  fseek(ZIN,-i,SEEK_END);
  Z_Read( CentralDir,i );
  for ( ; i > sizeof(EDIR); i-=1, (char*)p+=1 )
  {
   if (p->Sig == 0x06054B50)
   {
    memcpy(&ed,p,sizeof(EDIR));
    free(CentralDir);
    break;
   }
  }
 }
 if (ed.Sig != 0x06054B50)
#else
  Z_ERROR("Marcatore finale (0x06054B50) mancante");
#endif
 /* verifica un minimo di coerenza nella ENDDIR */
 if (ed.Disk != 0)
  Z_ERROR("L'archivio appare attualmente ripartito");

 /* Spazio per la Central Dir e il buffer di I/O */
 CentralDir = (char*) malloc(ed.Size);
 if (CentralDir==0)
  Z_ERROR("Poca memoria per caricare il corpo centrale dell'archivio");

 /* Bisogna leggere l'intera CDIR (per elaborarla) */
 fseek(ZIN,ed.Offset,SEEK_SET);
 Z_Read( CentralDir,ed.Size );
 if ( ((CENT*)CentralDir)->Sig != 0x02014B50)
  Z_ERROR("Marcatore centrale (0x02014B50) mancante");

 Process();
 
 free(CentralDir);

 return 0;
}
