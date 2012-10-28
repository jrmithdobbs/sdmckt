/* secret.h */
/*
    Please see the COPYING file distributed with this code for copyright and
    licensing information.
 */

#ifndef __SDMCKT_secret_h
#define __SDMCKT_secret_h

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <openssl/sha.h>

#include "sdmckt0/auth.h"

/* This comes from limits.h if it's not defined there set a sane default */
#ifndef PAGESIZE
#define PAGESIZE sysconf(_SC_PAGESIZE)
#endif
#define mlock(a,b) \
  mlock(((void *)(((size_t)(a)) & (~((PAGESIZE)-1)))),\
  (((((size_t)(a)) + (b) - 1) | ((PAGESIZE) - 1)) + 1) - (((size_t)(a)) & (~((PAGESIZE) - 1))))
#define munlock(a,b) \
  munlock(((void *)(((size_t)(a)) & (~((PAGESIZE)-1)))),\
  (((((size_t)(a)) + (b) - 1) | ((PAGESIZE) - 1)) + 1) - (((size_t)(a)) & (~((PAGESIZE) - 1))))

typedef struct SDMCKT_secret {
  uint8_t ver;
  uint8_t scrypt_len;
  uint16_t key_len;
  uint8_t share_M;
  uint8_t share_N;
  uint8_t pass_num;
  uint8_t oracle_num;
  uint8_t oracle_len;
  uint32_t data_len;
  uint8_t ** oracle_challenges;
  uint8_t ** pass_shares;
  uint8_t ** oracle_shares;
  uint8_t * data;
  uint8_t checksum[SHA256_DIGEST_LENGTH];
} SDMCKT_secret;

/* Constant for size of secret header data */
#define SDMCKT_secret_hsize 13
/* Constant for total size of secret meta data */
#define SDMCKT_secret_mdsize (SDMCKT_secret_hsize + SHA256_DIGEST_LENGTH)

/*
    create with empty data
    if (*key) is NULL a random one will be created and placed into key.
 */
SDMCKT_secret * SDMCKT_secret_new(uint8_t ** key, uint16_t key_len, uint8_t N,
        uint32_t data_len, uint8_t * data, SDMCKT_authlist * auth_data);
void SDMCKT_secret_free(SDMCKT_secret * secret);

void SDMCKT_secret_checksum(SDMCKT_secret * secret);

uint8_t * SDMCKT_secret_serialize(SDMCKT_secret * secret);
SDMCKT_secret * SDMCKT_secret_deserialize(uint8_t * input,
    SDMCKT_passphrase * pass);

int SDMCKT_secret_to_file(FILE * outfile, SDMCKT_secret * secret);
SDMCKT_secret * SDMCKT_secret_from_file(FILE * infile, SDMCKT_passphrase * pass);

uint8_t * SDMCKT_secret_get_key(SDMCKT_secret * secret,
    SDMCKT_authlist * auth_data);

uint8_t * SDMCKT_secret_get_data(SDMCKT_secret * secret, uint8_t * key);

int SDMCKT_secret_replace_data(SDMCKT_secret * secret, uint8_t * key,
    uint32_t data_len, uint8_t * data);
int SDMCKT_secret_uc_replace_data(uint8_t * secretustr, uint8_t * key,
    uint32_t data_len, uint8_t * data);

int SDMCKT_secret_replace_share(SDMCKT_secret * secret, uint8_t num,
    SDMCKT_auth * old_auth_data, SDMCKT_auth * new_auth_data,
    SDMCKT_passphrase * pass);
int SDMCKT_secret_uc_replace_share(uint8_t * secretustr, uint8_t num,
    SDMCKT_auth * old_auth_data, SDMCKT_auth * new_auth_data,
    SDMCKT_passphrase * pass);

SDMCKT_secret * SDMCKT_secret_resplit(SDMCKT_secret * secret, SDMCKT_authlist * oldauth,
    SDMCKT_authlist * newauth);

#endif
