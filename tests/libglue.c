/*
 * This file is part of libsparkcrypto.
 *
 * Copyright (C) 2010, Alexander Senier
 * Copyright (C) 2010, secunet Security Networks AG
 * All rights reserved.
 *
 * Redistribution  and  use  in  source  and  binary  forms,  with  or  without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of the  nor the names of its contributors may be used
 *      to endorse or promote products derived from this software without
 *      specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
 * IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
 * ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
 * BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
 * CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
 * SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
 * INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
 * CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
 * ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

static inline void
Authenticate_Generic
   (const EVP_MD  *Message_Digest,
    char          *Key,
    int            Key_Length,
    unsigned char *Message,
    int            Message_Length,
    unsigned char *Digest,
#ifndef DEBUG
   __attribute__((__unused__))
#endif
    unsigned int   Expected_Length);

 __attribute__((always_inline))

static inline void
Authenticate_Generic
   (const EVP_MD  *Message_Digest,
    char          *Key,
    int            Key_Length,
    unsigned char *Message,
    int            Message_Length,
    unsigned char *Digest,
#ifndef DEBUG
   __attribute__((__unused__))
#endif
    unsigned int   Expected_Length)
{
   unsigned int Length;

#ifdef DEBUG
   warn ("Authenticate_Generic called (key=%p, klen=%d, msg=%p, mlen=%d, dgst=%p, elen=%d)",
             Key, Key_Length, Message, Message_Length, Digest, Expected_Length);
#endif

   HMAC (Message_Digest,
         Key,
         Key_Length,
         Message,
         Message_Length,
         Digest,
         &Length);

#ifdef DEBUG
   if (Length != 2 * Expected_Length)
   {
      errx (1, "Algorithm as unexpected digest length (expected: %u, reported: %u)",
            Expected_Length, Length);
   }
#endif
};

void
Authenticate_SHA1
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_sha1(), Key, 64, Message, Message_Length / 8, Digest, 10);
}

void
Authenticate_SHA256
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_sha256(), Key, 64, Message, Message_Length / 8, Digest, 16);
}

void
Authenticate_SHA384
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_sha384(), Key, 128, Message, Message_Length / 8, Digest, 24);
}

void
Authenticate_SHA512
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_sha512(), Key, 128, Message, Message_Length / 8, Digest, 32);
}

void
Authenticate_RMD160
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_ripemd160(), Key, 64, Message, Message_Length / 8, Digest, 10);
}

void c_rsa_public_encrypt
   (unsigned char       *N,
    unsigned long long   N_Length,
    unsigned char       *E,
    unsigned long long   E_Length,
    const unsigned char *P,
    unsigned char       *C,
    unsigned long long  *Result)
{
   int rv = -1;
   RSA *key = RSA_new ();
   BIGNUM *n = BN_bin2bn(N, N_Length, NULL);
   BIGNUM *e = BN_bin2bn(E, E_Length, NULL);
   RSA_set0_key (key, n, e, NULL);

   rv = RSA_public_encrypt ((int)N_Length, P, C, key, RSA_NO_PADDING);
   if (rv == -1)
   {
       printf ("enc failed!\n");
       *Result = 1;
       return;
   }

   if (rv != N_Length)
   {
       printf ("wrong length (%ld vs. %ld)!\n", rv, N_Length);
       *Result = 2;
       return;
   }
 
   *Result = 0;
};

void c_rsa_private_decrypt
   (unsigned char       *N,
    unsigned long long   N_Length,
    unsigned char       *D,
    unsigned long long   D_Length,
    const unsigned char *C,
    unsigned char       *P,
    unsigned long long  *Result)
{
   int rv = -1;
   RSA *key = RSA_new ();
   BIGNUM *n = BN_bin2bn(N, N_Length, NULL);
   BIGNUM *d = BN_bin2bn(D, D_Length, NULL);
   RSA_set0_key (key, n, NULL, d);

   // FIXME: Why is RSA_FLAG_NO_BLINDING needed?
   RSA_set_flags (key, RSA_FLAG_NO_BLINDING);

   rv = RSA_private_decrypt ((int)N_Length, C, P, key, RSA_NO_PADDING);
   if (rv == -1)
   {
       printf ("dec failed!\n");
       *Result = 1;
       return;
   }

   if (rv != N_Length)
   {
       printf ("wrong length (%ld vs. %ld)!\n", rv, N_Length);
       *Result = 2;
       return;
   }
 
   *Result = 0;
};
