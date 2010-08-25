/*
 * Copyright (C) 2010  Alexander Senier <mail@senier.net>
 * Copyright (C) 2010  secunet Security Networks AG
 *
 * libsparkcrypto is  free software; you  can redistribute it and/or  modify it
 * under  terms of  the GNU  General Public  License as  published by  the Free
 * Software  Foundation;  either version  3,  or  (at  your option)  any  later
 * version.  libsparkcrypto  is  distributed  in  the  hope  that  it  will  be
 * useful,  but WITHOUT  ANY WARRANTY;  without  even the  implied warranty  of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * As a  special exception under  Section 7 of GPL  version 3, you  are granted
 * additional  permissions  described in  the  GCC  Runtime Library  Exception,
 * version 3.1, as published by the Free Software Foundation.
 *
 * You should  have received  a copy of  the GNU General  Public License  and a
 * copy  of  the  GCC  Runtime  Library  Exception  along  with  this  program;
 * see  the  files  COPYING3  and COPYING.RUNTIME  respectively.  If  not,  see
 * <http://www.gnu.org/licenses/>.
 */

#include <err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static void
Authenticate_Generic
   (const EVP_MD  *Message_Digest,
    char          *Key,
    int            Key_Length,
    unsigned char *Message,
    int            Message_Length,
    unsigned char *Digest,
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

   if (Length != 2 * Expected_Length)
   {
      errx (1, "Algorithm as unexpected digest length (expected: %u, reported: %u)",
            Expected_Length, Length);
   }
};

void
Authenticate_SHA256
   (char               *Key,
    unsigned char      *Message,
    unsigned long long  Message_Length,
    unsigned char      *Digest)
{
   Authenticate_Generic (EVP_sha256(), Key, 64, Message, Message_Length / 8, Digest, 16);
}
