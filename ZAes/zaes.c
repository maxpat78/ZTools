/*
 ZAES.C

 a Public Domain (and portable?) way to encode ZIP files with AES following
 WinZip's 9.0 scheme, thanks to PD LIBTOMCRYPT (http://www.libtomcrypt.org).
*/

/* ... but it's quite slow! WinZip 9 encrypts a 223 items (877K) archive in
 40", ZAES takes 1'27" *WITHOUT TESTING*!
 Profiling reveals that a great amount of time is spent in SHA1 hashing... */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>

#include <tomcrypt.h>

#ifdef GLADMAN_HMAC
 #include <hmac.h>
#else
 #ifdef USE_OPENSSL
  #include <openssl/hmac.h>
 #endif
#endif

#ifdef TBAR
#include "tbar.c"
#endif

#define Z_ERROR(x) fatal_error(x)

/* 32-bit types */
#ifndef DOS_16
 typedef unsigned int u32;
 typedef unsigned short u16;
#else
 typedef unsigned long u32;
 typedef unsigned int u16;
#endif

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
typedef struct _PK0102
{
        u32 Sig;
        u16 MadeBy;
        u16 ToExtract;
        u16 Flag;
        u16 CompMethod;
        u16 FileTime;
        u16 FileDate;
        u32 Crc32;
        u32 CompSize;
        u32 Size;
        u16 NameLen;
        u16 ExtraLen;
        u16 CommentLen;
        u16 Disk;
        u16 IntAtrr;
        u32 ExtAttr;
        u32 Offset;
} PK0102;


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
typedef struct _PK0506
{
        u32 Sig;
        u16 Disk;
        u16 StartDisk;
        u16 Entries;
        u16 Total;
        u32 Size;
        u32 Offset;
        u16 CommentLen;
} PK0506;


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
typedef struct _PK0304
{
        u32 Sig;
        u16 ToExtract;
        u16 Flag;
        u16 CompMethod;
        u16 FileTime;
        u16 FileDate;
        u32 Crc32;
        u32 CompSize;
        u32 Size;
        u16 NameLen;
        u16 ExtraLen;
} PK0304;

/*
    Extended AES header (both local & central) based on WinZip 9 specs:

        extra field header      2 bytes  (0x9901)
        size                    2 bytes  (7)
        version                 2 bytes  (actually, 0x0002)
        ZIP vendor              2 bytes  (actually, AE)
        strength                1 byte   (AES 1=128-bit key, 2=192, 3=256)
        actual compression      2 byte   (becomes 0x99 in LENT & CENT)

        content data, as follows:
        random salt (8, 12, 16 byte depending on key size)
        2-byte password verification value
        encrypted data
        10-byte HMAC-SHA1 authentication code for encrypted data

    NOTE: AE-1 seems to preserve CRC-32 on uncompressed data, while AE-2 sets
    it to zero: so we use AE-1, otherwise original CRC-32 couldn't be restored.
*/
typedef struct _AE_EXTRA
{
        u16 Sig;
        u16 Size;
        u16 Version;
        u16 Vendor;
        char Strength;
        u16 CompMethod;
} AE_EXTRA;

#pragma pack()



/* Global variables */
FILE *ZIN, *ZIN2, *ZOUT, *ZTMP;
u32 SaltSize, KeySize, Mode, AE2=0;
symmetric_CTR ctr;

#ifdef GLADMAN_HMAC
hmac_ctx hmac;
#elif defined(USE_OPENSSL)
HMAC_CTX hmac;
#else
hmac_state hmac;
#endif

void (*filter)(void* buf, u32 len);

struct {
 int Salt;
 int Key;
} KS[4] = { {0,0}, {8,16}, {12,24}, {16,32} };

char BUF[16+32*2+2*2];
char IV[16] = { 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

void fatal_error(char* s)
{
 puts(s);
 exit(666);
}

void* xmalloc(size_t len)
{
 char* p = (char*) malloc(len);
 if (!p) Z_ERROR("Can't allocate memory!");
 return p;
}

FILE* topen(char *name)
{
 u16 u, i;
 FILE *f;

 for (i=0; i<1000; i++) {
  sprng_read(&u, 4, 0);
  sprintf(name, "AE-%05X.TMP", u);
  f = fopen(name, "w+b");
  if (!f) continue;
  else return f;
 }
 Z_ERROR("Can't create a temporary file!");
 return 0; /* never reached */
}


/* Filters to treat data during I/O */
void encrypt_authenticate(void* buf, u32 len)
{
 if (ctr_encrypt(buf, buf, len, &ctr) != CRYPT_OK)
  Z_ERROR("Failed to encrypt");
#ifdef GLADMAN_HMAC
 hmac_sha1_data(buf, len, &hmac);
#else
 if (hmac_process(&hmac, buf, len) != CRYPT_OK)
  Z_ERROR("Failed to authenticate");
#endif
}

void authenticate_decrypt(void* buf, u32 len)
{
#ifdef GLADMAN_HMAC
 hmac_sha1_data(buf, len, &hmac);
#else
 if (hmac_process(&hmac, buf, len) != CRYPT_OK)
  Z_ERROR("Failed to authenticate");
#endif
 if (ctr_decrypt(buf, buf, len, &ctr) != CRYPT_OK)
  Z_ERROR("Failed to decrypt");
}


/* Functions to read/write data and copy file contents */
void safeRead(void* dst, FILE* In, u32 n)
{
 if (fread(dst,1,n,In) != n)
  Z_ERROR("Can't read requested bytes");
}

void safeWrite(FILE* Out, void* src, u32 n)
{
 if (fwrite(src,1,n,Out) != n)
  Z_ERROR("Can't write requested bytes");
}

char* IoBuF = 0; /* global I/O buffer */
#define fileCopy(a,b,c) _fileCopy(a,b,c,0)
#define fileFilter(a,b,c) _fileCopy(a,b,c,1)
void _fileCopy(FILE* fOut, FILE* fIn, u32 n, char filtering)
{
#ifndef DOS_16
#define BLOCK 64*1024
#else
#define BLOCK 1*1024
#endif
 if (!IoBuF)
 {
  IoBuF = (char*) xmalloc(BLOCK);
 }
 while (n > BLOCK)
 {
  safeRead(IoBuF, fIn, BLOCK);
  if (filtering) filter(IoBuF, BLOCK);
  safeWrite(fOut, IoBuF, BLOCK);
  n -= BLOCK;
 }
 safeRead(IoBuF, fIn, n);
 if (filtering) filter(IoBuF, n);
 safeWrite(fOut, IoBuF, n);
}

void getp(char* pw, int len)
{
 int i;
 for(i=0, --len; i < len; (i<0)? i=0 : i++)
 {
  pw[i] = (char) getch();
//~ printf("got code %02X\r", pw[i]);
  if (!pw[i]) { i--; continue; }
  if (pw[i] == 0x08) { i-=2; continue; }
  if (pw[i] == 0x0D) { pw[i] = 0; break; }
 }
//~ printf("\npassword typed was \"%s\"\n",pw);
}

#if 0
void dump(char* title, char*s, int len)
{
int j;
printf("%s=", title);
for(j = 0; j < len ; j++)
 printf("%02X", (unsigned char) s[j]);
printf("\n");
}
#endif


void Decrypt(PK0304 *le, char *password)
{
 char *salt, *key1, *key2, *check, digest[40];
 u32 key_len, dig_len = 40, start, xlen;
 AE_EXTRA ae;

 start = ftell(ZIN);
 /* Searches for AE-1 header */
 fseek(ZIN, le->NameLen, SEEK_CUR);
 for(xlen=le->ExtraLen; xlen;)
 {
  safeRead(&ae, ZIN, 4);
  xlen -= (4 + ae.Size);
  if (ae.Sig == 0x9901)
  {
   safeRead(&ae.Version, ZIN, 7);
   continue;
  }
  fseek(ZIN, ae.Size, SEEK_CUR);
 }
 if (ae.Sig != 0x9901)
  Z_ERROR("Fatal! Can't find AE extra header!");
 if (ae.Strength < 1 || ae.Strength > 3)
  Z_ERROR("Bad encryption strength");
 SaltSize = KS[ae.Strength].Salt;
 KeySize = KS[ae.Strength].Key;

 salt = BUF;
 key1 = salt+SaltSize;
 key2 = key1+KeySize;
 check = key2+KeySize;
 key_len = KeySize*2+2;

 /* Loads salt and password check value, and regenerates original crypto material */
 fseek(ZIN, start+le->NameLen+le->ExtraLen, SEEK_SET);
 safeRead(salt, ZIN, SaltSize);
 safeRead(check+2, ZIN, 2);
point1:
 if (pkcs_5_alg2(password, strlen(password), salt, SaltSize, 1000, 0, key1, &key_len) != CRYPT_OK)
  Z_ERROR("Failed to derive encryption keys");
 if (memcmp(check, check+2, 2))
 {
  printf("\nCan't decrypt data: try another password.\nNew password: ");
  getp(password, 128);
  printf("\n");
  goto point1;
 }
 if (ctr_start(0, IV, key1, KeySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr) != CRYPT_OK)
  Z_ERROR("Failed to setup AES CTR decoder");
#ifdef GLADMAN_HMAC
 hmac_sha1_begin(&hmac);
 hmac_sha1_key(key2, KeySize, &hmac);
#else
 if (hmac_init(&hmac, 0, key2, KeySize) != CRYPT_OK)
  Z_ERROR("Failed to setup HMAC-SHA1");
#endif
 /* Adjusts local header */
 le->Flag ^= 1;
 le->CompMethod = ae.CompMethod;
 le->ExtraLen -= 11;
 le->CompSize -= (SaltSize + 12);
 /* Writes local header and copies extra, except 0x9901 */
 safeWrite(ZOUT, le, sizeof(PK0304));
 fseek(ZIN, start, SEEK_SET);
 fileCopy(ZOUT, ZIN, le->NameLen);
 for(xlen=le->ExtraLen+11; xlen;)
 {
  safeRead(&ae, ZIN, 4);
  xlen -= (4 + ae.Size);
  if (ae.Sig == 0x9901)
  {
   safeRead(&ae.Version, ZIN, 7);
   continue;
  }
  safeWrite(ZOUT, &ae, 4);
  fileCopy(ZOUT, ZIN, ae.Size);
 }
 fseek(ZIN, SaltSize+2, SEEK_CUR);

 fileFilter(ZOUT, ZIN, le->CompSize);

#ifdef GLADMAN_HMAC
 hmac_sha1_end(digest, dig_len, &hmac);
#else
 if (hmac_done(&hmac, digest, &dig_len) != CRYPT_OK)
  Z_ERROR("Failed to computate HMAC");
#endif
 /* Retrieves and checks HMACs */
 safeRead(digest+10, ZIN, 10);
 if (memcmp(digest, digest+10, 10))
  printf(" authentication failed, contents were lost!");
 ctr_done(&ctr);
}


void Encrypt(PK0304* le, AE_EXTRA* ae, char* password)
{
 char *salt, *key1, *key2, *check, digest[40];
 u32 key_len = KeySize*2 + 2;
 u32 dig_len = 40;

 salt = BUF;
 key1 = salt+SaltSize;
 key2 = key1+KeySize;
 check = key2+KeySize;

 /* Gets a random salt (8-16 byte) */
 sprng_read(salt, SaltSize, 0);

 /* Generates 2 keys for AES and HMAC, plus 2-byte password verification value */
 if (pkcs_5_alg2(password, strlen(password), salt, SaltSize, 1000, 0, key1, &key_len) != CRYPT_OK)
  Z_ERROR("Failed to derive encryption keys");

// dump("salt", salt, SaltSize);
// dump("key", key1, KeySize);

 if (ctr_start(0, IV, key1, KeySize, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr) != CRYPT_OK)
  Z_ERROR("Failed to setup AES CTR encoder");
#ifdef GLADMAN_HMAC
 hmac_sha1_begin(&hmac);
 hmac_sha1_key(key2, KeySize, &hmac);
#else
 if (hmac_init(&hmac, 0, key2, KeySize) != CRYPT_OK)
  Z_ERROR("Failed to setup HMAC-SHA1");
#endif
 if (AE2) le->Crc32 = 0;
 le->Flag |= 1;
 le->CompMethod = 99;
 le->ExtraLen += 11;
 le->CompSize += SaltSize + 12; /* variable salt, fixed password check and hmac */

 safeWrite(ZOUT, le, sizeof(PK0304));
 fileCopy(ZOUT, ZIN, le->NameLen+le->ExtraLen-11);
 safeWrite(ZOUT, ae, 11);
 safeWrite(ZOUT, salt, SaltSize);
 safeWrite(ZOUT, check, 2);
 /* encrypt contents */
 fileFilter(ZOUT, ZIN, le->CompSize-SaltSize-12);
#ifdef GLADMAN_HMAC
 hmac_sha1_end(digest, dig_len, &hmac);
#else
 if (hmac_done(&hmac, digest, &dig_len) != CRYPT_OK)
  Z_ERROR("Failed to computate HMAC");
#endif
 safeWrite(ZOUT, digest, 10);
 ctr_done(&ctr);
}


int main(int argc,char** argv)
{
 char pm, operation=-1, found=1, pw1[128], pw2[128], ae1[15], ae2[15];
 u32 i;
 PK0102 ce;
 PK0304 le;
 PK0506 ed;

 for (pm=1; pm < argc; pm++)
 {
  char opt;
  if (argv[pm][0] != '/') continue;

  if (argv[pm][1] == '?') {
   printf( "Encrypts or decrypts an archive following WinZip(R) 9 specifications.\n\n" \
"ZAES /D | /E:keysize [/2] archive.zip\n\n" \
"  /D         decrypts AES encrypted entries\n" \
"  /E:keysize encrypts with 128, 192 or 256-bit keys (keysize 1, 2 or 3)\n" \
"  /2         AE-2 format (sets CRC-32 to zero)\n");
   return 1;
  }

  opt = toupper(argv[pm][1]);
  if (opt== 'E') {
   Mode = atol(&argv[pm][3]);
   operation = 0;
   filter = encrypt_authenticate;
   if (Mode < 1 || Mode > 3)
    Z_ERROR("Bad encryption mode specified!");
   SaltSize = KS[Mode].Salt;
   KeySize = KS[Mode].Key;
   found++;
   continue;
  }

  if (opt== 'D') {
   operation = 1;
   filter = authenticate_decrypt;
   found++;
   continue;
  }

  if (opt== '2') {
   AE2 = 1;
   found++;
   printf("WARNING: according to AE-2 specifications, CRC-32 will be set to zero\n"\
"in encrypted entries. Reverting to original archive after decryption will\n"\
"be impossible with this utility!\n");
   continue;
  }
 }
 argv+=found;
 argc-=found;

 if (operation == -1) Z_ERROR("You must specify /E or /D switch!\nTry ZAES /?");
 if (argc < 1) Z_ERROR("You must give a ZIP archive to process!");

 register_prng(&sprng_desc);
 register_cipher(&aes_desc);
 register_hash(&sha1_desc);
//~ printf("DEBUG: sha1 id=%d, aes id=%d\n", find_hash("sha1"), find_cipher("aes"));

 if ( (ZIN=fopen(argv[0],"rb")) == 0 || (ZIN2=fopen(argv[0],"rb")) == 0 )
  Z_ERROR("Can't open input ZIP archive");

 if ( (ZOUT=topen(ae1)) == 0 || (ZTMP=topen(ae2)) == 0)
  Z_ERROR("Can't open temporary output files");

 setvbuf(ZIN , 0, _IOFBF, BLOCK);
 setvbuf(ZOUT, 0, _IOFBF, BLOCK);

 /* assumiamo uno ZIP senza commento! */
 fseek(ZIN2,-22,SEEK_END);
 safeRead(&ed, ZIN2, sizeof(PK0506));

 if (ed.Sig != 0x06054B50)
#ifdef HANDLE_COMMENT
 {
  fseek(ZIN2, -0xFFFF, SEEK_END);
  fread(p, 1, 4, ZIN2);
#else
  Z_ERROR("End directory marker not found!");
#endif
 /* verifica un minimo di coerenza nella ENDDIR */
 if (ed.Disk != 0)
  Z_ERROR("Can't process a spanned archive");

 while(1) {
  printf("Enter password: ");
  getp(pw1, 128);
  if (strlen(pw1) < 8 && !operation) {
   printf("\rFor your safety, please use a password of 8 characters or more.\n");
   continue;
  }
  if (operation) {
   printf("\n");
   break;
  }
  printf("\rVerify password: ");
  getp(pw2, 128);
  if (strcmp(pw1, pw2)) {
   printf("Passwords don't match!\n");
   continue;
  }
  printf("\n");
  break;
 }

#define PUTN(x) { fileCopy(stdout, ZIN, x.NameLen); fseek(ZIN, -x.NameLen, SEEK_CUR); }

 fseek(ZIN2, ed.Offset, SEEK_SET);
 for (i=0; i < ed.Total; i++)
 {
   safeRead(&ce, ZIN2, sizeof(PK0102));
   if (ce.Sig != 0x02014B50)
    Z_ERROR("Expected central directory marker not found");
   /* Assume i dati corretti dalla LE */
   fseek(ZIN, ce.Offset, SEEK_SET);
   safeRead(&le, ZIN, sizeof(PK0304));
   if (le.Sig != 0x04034B50)
    Z_ERROR("Expected local entry marker not found");
   if ( ((le.Flag & 1) && !operation) || /* doesn't encrypt already encrypted */
        (!(le.Flag & 1) && operation) || /* doesn't decrypt already decrypted */
        ((le.Flag & 1) && operation && le.CompMethod != 99) || /* doesn't decrypt not AES encrypted */
        !le.CompSize )
   {
    ce.Offset = ftell(ZOUT);
    safeWrite(ZOUT, &le, sizeof(PK0304));
    printf("  copying: "); PUTN(le);
    fileCopy(ZOUT, ZIN, le.NameLen+le.ExtraLen+le.CompSize);
    printf("\n");
    safeWrite(ZTMP, &ce, sizeof(PK0102));
    fileCopy(ZTMP, ZIN2, ce.NameLen+ce.ExtraLen);
    continue;
   }
   if (!operation)
   {
    AE_EXTRA ae = {0x9901, 7, AE2+1, 0x4541, Mode, 0};
    ae.CompMethod = ce.CompMethod;
    ce.CompMethod = 99;
    if (AE2) ce.Crc32 = 0;
    ce.Flag |= 1;
    ce.ExtraLen += 11;
    ce.CompSize += SaltSize + 12; /* variable salt, fixed password check and hmac */
    ce.Offset = ftell(ZOUT);
    safeWrite(ZTMP, &ce, sizeof(PK0102));
    fileCopy(ZTMP, ZIN2, ce.NameLen+ce.ExtraLen-11);
    safeWrite(ZTMP, &ae, 11);
    printf("  encrypting: "); PUTN(le);
    Encrypt(&le, &ae, pw1);
    printf("\n");
   }
   else
   {
    ce.Offset = ftell(ZOUT);
    printf("  decrypting: "); PUTN(le);
    Decrypt(&le, pw1); /* Decrypts contents */
    printf("\n");
    ce.CompMethod = le.CompMethod;
    if (AE2) ce.Crc32 = 0;
    ce.Flag ^= 1;
    ce.ExtraLen -= 11;
    ce.CompSize = le.CompSize;
    safeWrite(ZTMP, &ce, sizeof(PK0102));
    /* Copy the extra data (may be LE != CE) */
    fileCopy(ZTMP, ZIN2, ce.NameLen);
    for(ce.ExtraLen+=11; ce.ExtraLen;)
    {
     u16 u[2];
     safeRead(u, ZIN2, 4);
     ce.ExtraLen -= (4 + u[1]);
     if (u[0] == 0x9901)
     {
      fseek(ZIN2, u[1], SEEK_CUR);
      continue;
     }
     safeWrite(ZTMP, u, 4);
     fileCopy(ZTMP, ZIN2, u[1]);
    }
   }
 }

 ed.Offset = ftell(ZOUT); /* new central directory start */
 ed.Size = ftell(ZTMP); /* new central directory size */
 fseek(ZTMP, 0, SEEK_SET);
 fclose(ZIN);
 fclose(ZIN2);
 /* Copies central directory */
 fileCopy(ZOUT, ZTMP, ed.Size);
 safeWrite(ZOUT, &ed, sizeof(PK0506));
 fclose(ZTMP);
 fclose(ZOUT);
 remove(ae2);
 if (remove(argv[0]))
 {
  printf("Can't remove old archive; new one is in file '%s'\n", ae1);
 } else
 if (rename(ae1, argv[0]))
 {
  printf("Can't rename old archive; new one is in file '%s'\n", ae1);
 }
 memset(&BUF, 0, sizeof(BUF));
 memset(&ctr, 0, sizeof(ctr));
 memset(pw1, 0, 128);
 memset(pw2, 0, 128);
 return 0;
}
