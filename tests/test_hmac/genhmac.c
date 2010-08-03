#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
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
   int key_len, msg_len;

   unsigned int dgst_len;
   unsigned char dgst[EVP_MAX_MD_SIZE];

   if (argc != 4)
   {
      errx (1, "Insufficient arguments: genhmac <key_file> <message_file> <digest_output_file>\n");
   }

   map_file (argv[1], &key, &key_len);
   map_file (argv[2], &msg, &msg_len);

   HMAC (EVP_sha512(),
         key,
         key_len,
         (unsigned char *)msg,
         msg_len,
         dgst,
         &dgst_len);

   printf ("DIGEST has length %d\n", dgst_len);

   fd = open (argv[3], O_CREAT|O_TRUNC|O_RDWR);
   if (fd == -1)
   {
      err (1, "Error opening output file: %s\n", argv[3]);
   }

   if (write (fd, dgst, dgst_len) == -1)
   {
      err (1, "Error writing digest to file\n");
   };

   close (fd);
   return 0;
}
