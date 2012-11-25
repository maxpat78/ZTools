#include <tomcrypt.h>

void main()
{
 char key[16];
 int key_len = 16;
 register_hash(&sha1_desc);
 pkcs_5_alg2("password", 8, "abcdefgh", 8, 50000, 0, key, &key_len);
}
