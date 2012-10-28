/* auth.c */
/* gcc -std=c89 -pedantic -Wall -g -c auth.c */
/*
    Please see the COPYING file distributed with this code for copyright
    and licensing information.
 */

#include "sdmckt0/auth.h"

/* Create a node */
SDMCKT_auth * SDMCKT_auth_vnew(SDMCKT_ATYPE type, va_list ap)
{
  SDMCKT_auth * new_auth = NULL;
  uint8_t * temp = NULL;

  new_auth = SDMCKT_malloc(sizeof(SDMCKT_auth));
  if (new_auth != NULL) {
    new_auth->generic.type = type;
    switch(type) {
      case PASS_AUTH:
        new_auth->pass.len = (uint16_t)va_arg(ap, int);
        new_auth->pass.passphrase = SDMCKT_malloc(new_auth->pass.len
            * sizeof(uint8_t));
        if (new_auth->pass.passphrase != NULL) {
          memcpy(new_auth->pass.passphrase, va_arg(ap, uint8_t *),
              new_auth->pass.len);
        } else {
          free(new_auth);
          new_auth = NULL;
        }
        break;
      case ORACLE_AUTH:
        new_auth->oracle.len = (uint16_t)va_arg(ap, int);
        new_auth->oracle.challenge = SDMCKT_malloc(new_auth->oracle.len
            * sizeof(uint8_t));
        if (new_auth->oracle.challenge != NULL) {
          temp = va_arg(ap, uint8_t *);
          if (temp == NULL) {
            if (SDMCKT_fetch_good_random(new_auth->oracle.challenge,
                  new_auth->oracle.len, "/dev/random")
                != new_auth->oracle.len) {
              SDMCKT_free(new_auth, sizeof(SDMCKT_auth));
              new_auth = NULL;
            }
          } else {
            memcpy(new_auth->oracle.challenge, temp, new_auth->oracle.len);
          }
        } else {
          SDMCKT_free(new_auth, sizeof(SDMCKT_auth));
          new_auth = NULL;
        }
        if (new_auth != NULL) {
          new_auth->oracle.resp_len = (uint16_t)va_arg(ap, int);
          new_auth->oracle.func = va_arg(ap, SDMCKT_oracle_func);
          new_auth->oracle.resp = NULL;
        }
        break;
      default:
        free(new_auth); new_auth = NULL;
    }
  }

  return new_auth;
}
/* Public interface */
SDMCKT_auth * SDMCKT_auth_new(SDMCKT_ATYPE type, ...) {
  va_list ap;
  SDMCKT_auth * ret;
  va_start(ap, type);
  ret = SDMCKT_auth_vnew(type, ap);
  va_end(ap);
  return ret;
}
/* Free a node */
void SDMCKT_auth_free(SDMCKT_auth * node)
{
  switch (node->generic.type) {
    case ORACLE_AUTH:
      node->oracle.func = NULL;
      if (node->oracle.resp != NULL) {
        SDMCKT_free(node->oracle.resp, node->oracle.resp_len);
      }
      node->oracle.resp_len = 0;
      node->oracle.resp = NULL;
    case PASS_AUTH:
    case GENERIC_AUTH:
      SDMCKT_free(node->generic.str, node->generic.len);
      node->generic.len = 0;
    default:
      break;
  }
  SDMCKT_free(node,sizeof(SDMCKT_auth));
}

int SDMCKT_oracle_query(SDMCKT_oracle * oracle) {
  int ret = 0;
  if (oracle->resp == NULL) {
    ret = (*oracle->func)(oracle);
    if (ret == 0 && oracle->resp == NULL) {
      ret = -1;
    }
  }
  return ret;
}

void SDMCKT_oracle_clearresp(SDMCKT_oracle * oracle) {
  if (oracle->resp != NULL) {
    memset(oracle->resp, 0, oracle->resp_len);
    SDMCKT_free(oracle->resp, oracle->resp_len);
    oracle->resp = NULL;
  }
}

/* Create a "list" */
SDMCKT_authlist * SDMCKT_authlist_new(uint8_t pass_num, uint8_t oracle_num)
{
  SDMCKT_authlist *new_list = NULL;

  new_list = malloc(sizeof(SDMCKT_authlist));
  if (new_list != NULL) {
    new_list->pass_num = pass_num;
    new_list->oracle_num = oracle_num;
    new_list->auth = malloc(sizeof(SDMCKT_auth) * (pass_num + oracle_num));
    if (new_list->auth == NULL) {
      free(new_list);
      new_list = NULL;
    }
  }

  return new_list;
}

/* Free a "list" and all nodes */
void SDMCKT_authlist_free(SDMCKT_authlist * list)
{
  uint8_t i;
  
  for (i = 0; i < list->pass_num + list->oracle_num; i++) {
    if (list->auth[i] != NULL) {
      SDMCKT_auth_free(list->auth[i]);
    }
  }
  free(list->auth);
  free(list);
}

/* Return a given auth instance */
SDMCKT_auth * SDMCKT_authlist_getitem(SDMCKT_authlist * list,
    SDMCKT_ATYPE type, uint8_t num)
{
  if (type == ORACLE_AUTH) {
    num += list->pass_num;
    if (num > list->pass_num + list->oracle_num)  {
      return NULL;
    }
  } else {
    if (num > list->pass_num)  {
      return NULL;
    }
  }

  return list->auth[num];
}

/* Return a given passphrase */
SDMCKT_passphrase * SDMCKT_authlist_getpass(SDMCKT_authlist *list, uint8_t n)
{
  return &SDMCKT_authlist_getitem(list, PASS_AUTH, n)->pass;
}

/* Return a given passphrase as union */
SDMCKT_auth * SDMCKT_authlist_getpass_union(SDMCKT_authlist *list, uint8_t n)
{
  return SDMCKT_authlist_getitem(list, PASS_AUTH, n);
}

/* Return a given oracle */
SDMCKT_oracle * SDMCKT_authlist_getoracle(SDMCKT_authlist * list, uint8_t n)
{
  return &SDMCKT_authlist_getitem(list, ORACLE_AUTH, n)->oracle;
}

/* Return a given oracle as union */
SDMCKT_auth * SDMCKT_authlist_getoracle_union(SDMCKT_authlist * list, uint8_t n)
{
  return SDMCKT_authlist_getitem(list, ORACLE_AUTH, n);
}

uint8_t SDMCKT_authlist_num(SDMCKT_authlist * list)
{
  return list->pass_num + list->oracle_num;
}

uint8_t SDMCKT_authlist_passnum(SDMCKT_authlist * list)
{
  return list->pass_num;
}

uint8_t SDMCKT_authlist_oraclenum(SDMCKT_authlist * list)
{
  return list->oracle_num;
}

/* Add existing node to appropriate list */
int SDMCKT_authlist_add(SDMCKT_authlist * list, uint8_t num,
    SDMCKT_auth * auth_data)
{
  uint8_t i = num;
  if (auth_data != NULL) {
    switch (auth_data->generic.type) {
      case PASS_AUTH:
        break;
      case ORACLE_AUTH:
        i += list->pass_num;
        break;
      default:
        break;
    }
    list->auth[i] = auth_data;
    return 0;
  }
  return 1;
}

/* Create and append a node to the appropriate list */
int SDMCKT_authlist_add_new(SDMCKT_authlist * list, uint8_t num,
    SDMCKT_ATYPE type, ...)
{
  va_list pa;
  SDMCKT_auth * auth_data = NULL;

  va_start(pa, type);
  auth_data = SDMCKT_auth_vnew(type, pa); 
  va_end(pa);

  if (auth_data != NULL) {
    return SDMCKT_authlist_add(list, num, auth_data);
  } else {
    return -1;
  }
}

