#include "vanity.h"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#ifdef USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/rand.h>
#else
#include "sha1.h"
#include <time.h>
/** shitty home grown random number generator */
static void RAND_bytes(char * dataptr, size_t datalen)
{
  long int r;
  size_t s = sizeof(long int);
  size_t idx = 0;
  srandom(time(NULL));
  while(idx + s < datalen) {
    r = random();
    memcpy(dataptr+idx, &r, s);
    idx += s;
  }
  if (idx < datalen) {
    r = random();
    memcpy(dataptr+idx, &r, datalen - idx);
  }
}
#endif

/** check if this digest matches our vanity prefix */
static int vanity_match(char * vanity, size_t vlen, uint8_t * digest)
{
  int i = 0;
  uint8_t v;
  while(i < SHA_DIGEST_LENGTH) {
    v = *(vanity++);
    if (v != digest[i++] ) {
      break;
    }
  }
  return i == (vlen + 1);
}

static void build_info(metafile_t *m, char ** info, unsigned char * hash_string)
{
  char *a, *b;
  size_t piece_size = m->pieces * SHA_DIGEST_LENGTH;
  size_t infolen = 0;
  flist_t * list = m->file_list;
  if(!m->target_is_directory) 
    infolen += asprintf(info, "6:lengthi%" PRIoff "e", list->size);
  else {
    infolen += asprintf(info, "5:filesl");
    for(; list; list = list->next) {
      infolen += asprintf(info, "d6:lengthi%" PRIoff "e4:pathl", list->size);
      a = list->path;
      /* while there are subdirectories before the filename.. */
      while ((b = strchr(a, DIRSEP_CHAR)) != NULL) {
       
       
        *b = '\0';
        /* print it bencoded */
        infolen += asprintf(info, "%lu:%s", (unsigned long)strlen(a), a);
        /* undo our alteration to the string */
        *b = DIRSEP_CHAR;
        /* and move a to the beginning of the next
           subdir or filename */
        a = b + 1;
      }
      /* now print the filename bencoded and end the
         path name list and file dictionary */
      infolen += asprintf(info, "%lu:%see", (unsigned long)strlen(a), a);
    }
    
    /* whew, now end the file list */
    infolen += asprintf(info, "e");
  }   
  

 	/* the info section also contains the name of the torrent,
	   the piece length and the hash string */
	infolen += asprintf(info, "4:name%lu:%s12:piece lengthi%ue6:pieces%u:",
           (unsigned long)strlen(m->torrent_name), m->torrent_name,
           m->piece_length, piece_size);

  /* write placeholders for piece data  */
  while(piece_size--)
    asprintf(info, "x");
  
	/* set the private flag */
	if (m->private)
		asprintf(info, "7:privatei1e");

	if (m->source)
		asprintf(info, "6:source%lu:%s", (unsigned long)strlen(m->source), m->source);

  /** vanity */
  asprintf(info, "6:vanity%lu:", (unsigned long)VCOOKIE_SIZE);
  /** put piece data */
  memcpy((*info)+infolen, hash_string, m->pieces * SHA_DIGEST_LENGTH);
}

/** bruteforce generation of vanity infohash */
void bruteforce_vanity(metafile_t *m, unsigned char *hash_string)
{
  SHA_CTX sha;
  uint8_t digest[SHA_DIGEST_LENGTH];
  char * info = NULL;
  size_t vlen = strlen(m->vanity);
  size_t infolen = 0;
  /* build info section */
  build_info(m, &info, hash_string);
  infolen = strlen(info);
  /* allocate vcookie */
  m->vcookie = malloc(VCOOKIE_SIZE);
  
  /* it begins ... */
  printf("bruteforcing vanity infohash for '%s' ...", m->vanity);
  fflush(stdout);
  do {
    /* randomize vcookie */
    RAND_bytes(m->vcookie, VCOOKIE_SIZE);
    /* init sha context */
    SHA1_Init(&sha);
    /* hash info section */
    SHA1_Update(&sha, info, infolen);
    SHA1_Update(&sha, m->vcookie, VCOOKIE_SIZE);
    /* finalize */
    SHA1_Final(digest, &sha);
    /* free unused */
  } while(!vanity_match(m->vanity, vlen, digest));
  printf(" WEW done!\n");
  fflush(stdout);
  free(info);
}
