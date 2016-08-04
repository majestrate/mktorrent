#ifndef _MKTORRENT_VANITY_H
#define _MKTORRENT_VANITY_H
#include "mktorrent.h"

/** size of vcookie in bytes */
#define VCOOKIE_SIZE 24

/** do vanity bruteforce */
void bruteforce_vanity(metafile_t * m, unsigned char *hash_string);

#endif


