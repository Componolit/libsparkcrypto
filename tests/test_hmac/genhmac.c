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
      errx (1, "Insufficient arguments: genhmac {sha256|sha384|sha512|rmd160} <key_file> <message_file> <digest_output_file> [length]\n");
   }

   algo      = argv[1];
   key_file  = argv[2];
   msg_file  = argv[3];
   dgst_file = argv[4];

   /* select algorithm */
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
