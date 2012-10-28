/* util.c */
/* gcc -std=c89 -pedantic -Wall -g -c util.c */
/*
    Please see the COPYING file distributed with this code for copyright
    and licensing information.
 */

#include "sdmckt0/util.h"

void SDMCKT_debug_tracking(char * file, uint16_t line) {
  printf("Failure occured at %s:%d\n", file, line);
}

void * SDMCKT_malloc(size_t sz) {
  void * ptr;

  ptr = calloc(sz,1);
  if (ptr == NULL) {
    return ptr;
  }
#ifdef WORKING_MLOCK
  if (mlock(ptr,sz) == -1) {
    free(ptr);
    ptr = NULL;
    return ptr;
  }
#endif
  return ptr;
}

void SDMCKT_free(void *ptr, size_t sz) {
  memset(ptr, 0, sz);
#ifdef WORKING_MLOCK
  munlock(ptr, sz);
#endif
  free(ptr);
}

/*
    Reads 3x the requested amount of  random data from /dev/random.
    buf = buffer to store random data in
    len = length of buffer (ammount of random data)
    randompath = filesystem path to random device to use
 */
size_t SDMCKT_fetch_good_random(uint8_t * buf, size_t len, const char * random_path)
{
  FILE * random_dev = NULL;
  uint8_t temp[3];
  size_t i = 0, j;
  int tempc = 0;

  errno = 0;
  random_dev = fopen(random_path, "r");
  if (random_dev == NULL) {
    perror("Problem opening random device");
    return i;
  }

  for (i = 0; i < len; i++) {
    memset(temp,0,3);
    for (j = 0; j < 3; j++) {
      tempc = fgetc(random_dev);
      if(tempc == EOF) {
        goto randerr;
      }
      temp[j] = (uint8_t)tempc;
    }
    buf[i] = temp[temp[2] % 2];
  }

randerr:
  fclose(random_dev);
  /* If there were errors reading random data don't return any! */
  if (i != len) {
    memset(buf,0,len);
    i = 0;
  }
  return i;
}

