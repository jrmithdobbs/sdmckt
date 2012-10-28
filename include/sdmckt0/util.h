/* util.h */
/*
    Please see the COPYING file distributed with this code for copyright and
    licensing information.
 */

#ifndef __SDMCKT_UTIL_H
#define __SDMCKT_UTIL_H

#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>

#include "config.h"

void SDMCKT_debug_tracking(char * file, uint16_t line);

void * SDMCKT_malloc(size_t sz);
void SDMCKT_free(void *ptr, size_t sz);
size_t SDMCKT_fetch_good_random(uint8_t * buf, size_t len,
    const char * random_path);

#endif
