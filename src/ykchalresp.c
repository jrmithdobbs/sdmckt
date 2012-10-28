/*
  gcc -std=c89 -g -pedantic -I/usr/include/ykpers-1 \
    -DYKCHALRESP_TEST -c ykchalresp.c
  gcc -g -std=c89 -pedantic -static -o ykchalresp ykchalresp.o \
    -lykpers-1 -lpthread -lusb-1.0 -pthread -lrt -lyubikey
 */

/* This code is bastardized from ykchalresp.c in the ykpers package
   in order to meet the needs of this application. Hopefully a similar
   interface will be added to ykpers directly in the future.

   Modifications to this code are subject to the terms in the COPYING
   file distributed with this code. The original Copyright notice follows.
 */

/*
 * Copyright (c) 2011 Yubico AB.
 * All rights reserved.
 *
 * Author : Fredrik Thulin <fredrik@yubico.com>
 *
 * Some basic code copied from ykpersonalize.c.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>

#include <yubikey.h>
#include <ykpers.h>
#include <ykcore.h>

#include "sdmckt0/util.h"

static void report_yk_error()
{
  if (ykp_errno)
    fprintf(stderr, "Yubikey personalization error: %s\n",
      ykp_strerror(ykp_errno));
  if (yk_errno) {
    if (yk_errno == YK_EUSBERR) {
      fprintf(stderr, "USB error: %s\n",
        yk_usb_strerror());
    } else {
      fprintf(stderr, "Yubikey core error: %s\n",
        yk_strerror(yk_errno));
    }
  }
}

/*
 * These defs should really be provided by ykpers but are lacking in the
 * distributed headers. They come from ykdef.h in the ykpers distribution
 */
#define SLOT_CHAL_HMAC1   0x30  /* Write 64 byte challenge to slot 1, get HMAC-SHA1 response */
#define SLOT_CHAL_HMAC2   0x38  /* Write 64 byte challenge to slot 2, get HMAC-SHA1 response */

/* Returns 0 on error and length of response on success 
 * slot = 1 or 2 (slot on yubikey)
 * challenge = challenge data (must be 32 bytes)
 * response = 64 byte buffer
 */
int yubi_hmac_challenge_response(unsigned char slot, unsigned char *challenge,
    unsigned char *response)
{
  YK_KEY *yk = NULL;
  bool error = true;
  int exit_code = 0;
  int yk_cmd;
  unsigned int response_len = 0;

  if (!yk_init()) {
    printf("\nykchalresp.c:%d ykp_errno: %d yk_errno: %d\n", __LINE__, ykp_errno, yk_errno);
    exit_code = 2;
    goto err;
  }

  ykp_errno = 0;
  yk_errno = 0;

  if (!(yk = yk_open_first_key())) {
    printf("\nykchalresp.c:%d ykp_errno: %d yk_errno: %d\n", __LINE__, ykp_errno, yk_errno);
    exit_code = 1;
    goto err;
  }

  memset(response, 0, 64);

  switch(slot) {
  case 1:
    yk_cmd = SLOT_CHAL_HMAC1;
    break;
  case 2:
    yk_cmd = SLOT_CHAL_HMAC2;
    break;
  default:
    goto err;
  }

  while (! (
      yk_write_to_key(yk, yk_cmd, challenge, 32)
      && yk_read_response_from_key(yk, slot, YK_FLAG_MAYBLOCK,
          response, 64, 20, &response_len)
    ) ) {
    if (yk_errno == 4) {
      yk_errno = 0;
      sleep(1);
      continue;
    } else {
      printf("\nykchalresp.c:%d ykp_errno: %d yk_errno: %d\n", __LINE__, ykp_errno, yk_errno);
      exit_code = 4;
      goto err;
    }
  }

  if (response_len > 20) {
    memset(&response[20], 0, 44);
    response_len = 20;
  }

  exit_code = 0;
  error = false;

err:
  if (error || exit_code != 0) {
    report_yk_error();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
  }

  if (yk && !yk_close_key(yk)) {
    report_yk_error();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
  }

  if (!yk_release()) {
    report_yk_error();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
  }

  if (response_len == 0) {
    memset(response, 0, 64);
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
  }

  return response_len;
}

#ifdef YKCHALRESP_TEST

int main(int argc, char **argv) {
  char * encoded = "353f962fd41dc45f842be0e0e7888a9e8dba40a4db61bacc92dae628d90e4c4a";
  unsigned char response[20];
  unsigned char decoded[32];
  unsigned int i;

  printf("%s\n",encoded);
  yubikey_hex_decode((char *)decoded, encoded, sizeof(decoded));
  for (i = 0; i < 32; i++) {
    printf("%02x",decoded[i]);
  }
  printf("\n");

  memset(response,0,20);
  if(yubi_hmac_challenge_response(2,(unsigned char *)&decoded,(unsigned char *)&response) == 20) {
    for (i = 0; i < 20; i++) {
      printf("%02x",response[i]);
    }
    printf("\n");
  }
  return 0;
}

#endif
