//#define TEST_TIME

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <string.h>
#ifdef TEST_TIME
#include <time.h>
#endif

void fillBytes(register char* byteArray, register char* hexArray, int dataLen)
{
    int i;
    char byte[3];

    byte[2] = '\0';

    for (i = 0; i < dataLen; i++) 
    {
        byte[0] = *(hexArray);
        byte[1] = *(hexArray + 1);

        *byteArray = (char)strtoul(byte, NULL, 16);

        byteArray++;
        
        hexArray++;
        hexArray++;
    }
}

int main(int argc, char* argv[])
{
    char* passKey;
    char calculatedHash[MD5_DIGEST_LENGTH];
    
    char* originData;
    int originDataLen;
    char originHash[MD5_DIGEST_LENGTH];

    MD5_CTX md5hasher;

    char* characters = "abcdefghijklmnopqrstuvwxyz0123456789";
    int charactersCount = strlen(characters);
    int passStrlen = 0;

    char firstChar = *characters;
    char lastChar = *(characters + charactersCount - 1);
    register char lc = '9';

    register int i;
    register int v;
    register int comp;
    int j;

#ifdef TEST_TIME
    clock_t ta, tb;
#endif

    if (argc != 3) {
        printf("Too few arguments");
        return 2;
    }

    originDataLen = strlen(argv[1]) / 2;
    originData = (char*)malloc(originDataLen + MD5_DIGEST_LENGTH + 1);

    fillBytes(originData, argv[1], originDataLen);
    fillBytes(originHash, argv[2], MD5_DIGEST_LENGTH);

    passKey = originData + originDataLen;
    memset(passKey, 0, MD5_DIGEST_LENGTH + 1);

#ifdef TEST_TIME
    ta = clock();
#endif
    
    do {
        i = 0;
        comp = 0;

        do {
            if (i >= passStrlen) {
                for (j = MD5_DIGEST_LENGTH - 2; j >= 0; j--)
                    passKey[j + 1] = passKey[j];

                passKey[0] = firstChar;

                passStrlen++;
                if (passStrlen == 16) {
                    printf("Str overflow");
                    return 1;
                }
            }

            i++;
            v = passStrlen - i;
            lc = passKey[v];
            comp = (lc == lastChar);

            if (comp) {
                passKey[v] = firstChar;
            } else {
                passKey[v] = *(strchr(characters, lc) + 1);
            }
        } while (comp);

        //printf("passkey: %s\n", passKey);

        MD5_Init(&md5hasher);
        MD5_Update(&md5hasher, originData, originDataLen + MD5_DIGEST_LENGTH);
        MD5_Final(calculatedHash, &md5hasher);

    } while (memcmp(originHash, calculatedHash, MD5_DIGEST_LENGTH) != 0);

    printf("%s", passKey);

    free(originData);

#ifdef TEST_TIME
    tb = clock();
    printf("Cracking time: %f", (float)((tb - ta) / (float)CLOCKS_PER_SEC));
#endif
}
