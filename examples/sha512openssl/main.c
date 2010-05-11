#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

int
main()
{
    SHA512_CTX context;
    unsigned char md[SHA512_DIGEST_LENGTH];
    int i;
    unsigned char input[128];

    memset (&input, 0xea, sizeof (*input));

    SHA512_Init (&context);
    for (i = 1; i <= 1000000; i++)
    {
        SHA512_Update (&context, input, sizeof (*input));
    }
    SHA512_Final (md, &context);

    for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        printf ("%02x", md[i]);
    }
    printf ("\n");
}
