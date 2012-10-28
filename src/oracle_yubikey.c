#include <yubikey.h>
#include <ykpers.h>
#include "sdmckt0/oracle_yubikey.h"

/*
  return values:
  1 = malloc error (check errno)
  2 = error performing hmac request
*/
int yubikey_oracle_query(SDMCKT_oracle * oracle, int slot) {
  int ret = 0;
  uint8_t * tmpbuf = NULL;

  /* FIXME: hardcoded magic number */
  /* We need a temporary 64 byte buffer due to yubikey semantics */
  tmpbuf = SDMCKT_malloc(64 * sizeof(uint8_t));
  if (tmpbuf == NULL) {
    ret = 1;
  }

  if (ret == 0 && oracle->resp == NULL) {
    oracle->resp = SDMCKT_malloc(oracle->resp_len * sizeof(uint8_t));
    if (oracle->resp == NULL) {
      ret = 1;
    } else if (yubi_hmac_challenge_response(slot, oracle->challenge,
          tmpbuf) != oracle->resp_len) {
      SDMCKT_free(oracle->resp, oracle->resp_len);
      oracle->resp = NULL;
      ret = 2;
    } else {
      memcpy(oracle->resp, tmpbuf, oracle->resp_len);
    }
  }

  if (tmpbuf != NULL) {
    SDMCKT_free(tmpbuf, 64);
  }

#ifdef DEBUG
  if ( ret != 0 ) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  } 
#endif

  return ret;
}

int yubikey_oracle_query_slot1(SDMCKT_oracle * oracle)
{
  return yubikey_oracle_query(oracle, 1);
}

int yubikey_oracle_query_slot2(SDMCKT_oracle * oracle)
{
  return yubikey_oracle_query(oracle, 2);
}

