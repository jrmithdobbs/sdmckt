/* auth.h */
/*
    Please see the COPYING file distributed with this code for copyright and
    licensing information.
 */

#ifndef __SDMCKT_AUTH_H
#define __SDMCKT_AUTH_H

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "sdmckt0/util.h"

typedef enum {
  GENERIC_AUTH = 0u,
  PASS_AUTH,
  ORACLE_AUTH
} SDMCKT_ATYPE;

typedef struct SDMCKT_generic {
  SDMCKT_ATYPE type;
  uint16_t len;
  uint8_t * str;
} SDMCKT_generic;

typedef struct SDMCKT_passphrase {
  SDMCKT_ATYPE type;
  uint16_t len;
  uint8_t * passphrase;
} SDMCKT_passphrase;

struct SDMCKT_oracle;

typedef int (*SDMCKT_oracle_func)(struct SDMCKT_oracle *);

typedef struct SDMCKT_oracle {
  SDMCKT_ATYPE type;
  uint16_t len;
  uint8_t * challenge;
  uint16_t resp_len;
  uint8_t * resp;
  SDMCKT_oracle_func func;
} SDMCKT_oracle;

typedef union SDMCKT_auth {
  SDMCKT_generic generic;
  SDMCKT_passphrase pass;
  SDMCKT_oracle oracle;
} SDMCKT_auth;

typedef struct SDMCKT_authlist {
  uint8_t pass_num;
  uint8_t oracle_num;
  SDMCKT_auth ** auth;
} SDMCKT_authlist;

/* Create a node */
SDMCKT_auth * SDMCKT_auth_new(SDMCKT_ATYPE type, ...);
/* Free a node */
void SDMCK_auth_free(SDMCKT_auth * node);

/* Create a "list" */
SDMCKT_authlist * SDMCKT_authlist_new(uint8_t pass_num, uint8_t oracle_num);
/* Free a "list" and all nodes */
void SDMCKT_authlist_free(SDMCKT_authlist * list);

/* Add existing node to appropriate list */
int SDMCKT_authlist_add(SDMCKT_authlist * list, uint8_t num,
    SDMCKT_auth * auth_data);

/* Create and append a node to the appropriate list */
int SDMCKT_authlist_add_new(SDMCKT_authlist * list, uint8_t num,
    SDMCKT_ATYPE type, ...);

/* Get a given passphrase from an authlist */
SDMCKT_passphrase * SDMCKT_authlist_getpass(SDMCKT_authlist *list, uint8_t n);
/* Get a given oracle from an authlist */
SDMCKT_oracle * SDMCKT_authlist_getoracle(SDMCKT_authlist * list, uint8_t n);
/* Get a given passphrase from an authlist as union */
SDMCKT_auth * SDMCKT_authlist_getpass_union(SDMCKT_authlist *list, uint8_t n);
/* Get a given oracle from an authlist as union */
SDMCKT_auth * SDMCKT_authlist_getoracle_union(SDMCKT_authlist * list, uint8_t n);

/* Get counts */
uint8_t SDMCKT_authlist_num(SDMCKT_authlist * list);
uint8_t SDMCKT_authlist_passnum(SDMCKT_authlist * list);
uint8_t SDMCKT_authlist_oraclenum(SDMCKT_authlist * list);

int SDMCKT_oracle_query(SDMCKT_oracle * oracle);
void SDMCKT_oracle_clearresp(SDMCKT_oracle * oracle);

#endif
