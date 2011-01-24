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
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

void
map_file (const char  *file,
                char **mem,
                 int  *mem_size)
{
   int fd, rv;
   void *map_result = MAP_FAILED;
   struct stat sb;

   fd = open (file, O_RDONLY);
   if (fd == -1)
   {
      err (1, "Error opening '%s'", file);
   }

   rv = fstat (fd, &sb);
   if (rv == -1)
   {
      err (1, "Error stating '%s'", file);
   }

   map_result = mmap (NULL,         /* addr   */
                      sb.st_size,   /* length */
                      PROT_READ,    /* prot   */
                      MAP_SHARED,   /* flags  */
                      fd,           /* fd     */
                      0);           /* offset */
   if (map_result == MAP_FAILED)
   {
      err (1, "Error mapping '%s', size %llu", file, (unsigned long long)sb.st_size);
   }

   *mem      = map_result;
   *mem_size = sb.st_size;
}

int
main (int argc, char **argv)
{
   int fd;
   char *key, *msg;
   int key_len, msg_len, length;
   const char *algo, *key_file, *msg_file, *dgst_file;
   const EVP_MD *md = NULL;

   unsigned int dgst_len;
   unsigned char dgst[EVP_MAX_MD_SIZE];

   length = 0;

   if (argc != 5 && argc != 6)
   {
      errx (1, "Insufficient arguments: genhmac {sha1|sha256|sha384|sha512|rmd160} <key_file> <message_file> <digest_output_file> [length]\n");
   }

   algo      = argv[1];
   key_file  = argv[2];
   msg_file  = argv[3];
   dgst_file = argv[4];

   /* select algorithm */
   if (0 == strcmp (algo, "sha1")) md = EVP_sha1();
      else
   if (0 == strcmp (algo, "sha256")) md = EVP_sha256();
      else
   if (0 == strcmp (algo, "sha384")) md = EVP_sha384();
      else
   if (0 == strcmp (algo, "sha512")) md = EVP_sha512();
      else
   if (0 == strcmp (algo, "rmd160")) md = EVP_ripemd160();
      else
   errx (1, "Unknown algorithm: %s", algo);

   map_file (key_file, &key, &key_len);
   map_file (msg_file, &msg, &msg_len);

   if (argc == 6)
   {
      msg_len = atoi (argv[5]);
   }

   HMAC (md,
         key,
         key_len,
         (unsigned char *)msg,
         msg_len,
         dgst,
         &dgst_len);

   printf ("message has length %d, DIGEST %s has length %d\n", msg_len, algo, dgst_len);

   fd = open (dgst_file, O_CREAT|O_TRUNC|O_RDWR, 0644);
   if (fd == -1)
   {
      err (1, "Error opening output file: %s\n", dgst_file);
   }

   if (write (fd, dgst, dgst_len) == -1)
   {
      err (1, "Error writing digest to file\n");
   };

   close (fd);
   return 0;
}
