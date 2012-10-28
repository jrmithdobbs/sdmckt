#ifndef __SDMCKT_ORACLE_YUBIKEY_H
#define __SDMCKT_ORACLE_YUBIKEY_H

#include "sdmckt0/util.h"
#include "sdmckt0/auth.h"

int yubi_hmac_challenge_response(unsigned char slot, unsigned char *challenge,
    unsigned char *response);

int yubikey_oracle_query_slot1(SDMCKT_oracle * oracle);
int yubikey_oracle_query_slot2(SDMCKT_oracle * oracle);

#endif
