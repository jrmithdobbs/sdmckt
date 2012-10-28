/* secret.c */
/* gcc -std=c89 -pedantic -Wall -g -c secret.c */
/*
    Please see the COPYING file distributed with this code for copyright
    and licensing information.
 */

/* OpenBSD defines this in sys/types.h which util.h pulls in */
#ifndef __OpenBSD__
#include <arpa/inet.h>
#endif

#include "sdmckt0/util.h"

#include "scryptenc.h"

#include "sdmckt0/shamirs.h"
#include "sdmckt0/secret.h"
#include "sdmckt0/auth.h"


/*
    create with known data
    if (*key) is NULL a random one will be created and placed into key.
*/
SDMCKT_secret * SDMCKT_secret_new(uint8_t ** key, uint16_t key_len, uint8_t N,
        uint32_t data_len, uint8_t * data, SDMCKT_authlist * auth_data)
{
  SDMCKT_secret * new_secret = NULL;
  uint8_t ** shares = NULL, err = 0;
  uint8_t * packedpass_share = NULL;
  size_t data_enc_len, share_enc_len, i;
  int scryptret = 0;

  /* Make sure key is ready for use! */
  if ((*key) == NULL) {
    (*key) = SDMCKT_malloc(key_len * sizeof(uint8_t));
    if ((*key) == NULL) {
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }

    i = SDMCKT_fetch_good_random((*key), key_len, "/dev/random");
    if (i != key_len) {
      free((*key));
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }
    i = 0;
  }
  
  new_secret = SDMCKT_malloc(sizeof(SDMCKT_secret));
  if (new_secret == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  /* FIXME: hardcoded magic number. */
  new_secret->ver = 0;
  /* FIXME: hardcoded magic number. */
  new_secret->scrypt_len = 127;
  new_secret->key_len = key_len;
  data_enc_len = data_len + new_secret->scrypt_len + 1;
  share_enc_len = new_secret->key_len + new_secret->scrypt_len + 1;
  new_secret->share_M = N;
  new_secret->share_N = N;
  new_secret->pass_num = SDMCKT_authlist_passnum(auth_data);
  new_secret->oracle_num = SDMCKT_authlist_oraclenum(auth_data);
  new_secret->oracle_len = auth_data->auth[new_secret->pass_num]->oracle.len;
  new_secret->data_len = data_len;

  new_secret->data = NULL;
  new_secret->oracle_challenges = NULL;
  new_secret->pass_shares = NULL;
  new_secret->oracle_shares = NULL;

  /* Store oracle challenges */
  new_secret->oracle_challenges = malloc(new_secret->oracle_num * sizeof(uint8_t *));
  if (new_secret->oracle_challenges == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  for (i = 0; i < new_secret->oracle_num; i++) {
    new_secret->oracle_challenges[i] = SDMCKT_malloc(new_secret->oracle_len * sizeof(uint8_t));
    if (new_secret->oracle_challenges[i] == NULL) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }
  }

  /* Create shares */
  shares = calloc(N+1,sizeof(uint8_t *));
  if (shares == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }
  
  shares[0] = (*key);
  for (i = 1; i <= N; i++) {
    shares[i] = SDMCKT_malloc(key_len * sizeof(uint8_t));
    if (shares[i] == NULL) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }
  }

  if (shamirs_split(N, N, key_len, shares, "/dev/random") != 0) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  /* Encrypt shares */
  /* Encrypt password shares */
  new_secret->pass_shares = malloc(new_secret->pass_num * sizeof(uint8_t **));
  if (new_secret->pass_shares == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  for (i = 0; i < new_secret->pass_num; i++) {
    size_t octlen = 0, j;

    if (new_secret->pass_num != 1) {
      packedpass_share = shares[i+1];
    } else {
      /* Pack oracle challenges in with passphrase share */
      octlen = new_secret->oracle_len * new_secret->oracle_num;

      packedpass_share = SDMCKT_malloc((octlen + new_secret->key_len) * sizeof(uint8_t));
      if (packedpass_share == NULL) {
        err += 1;
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        goto secret_error;
      }

      for (j = 0; j < new_secret->oracle_num; j++) {
        memcpy(&packedpass_share[j * new_secret->oracle_len],
            SDMCKT_authlist_getoracle(auth_data, j / new_secret->oracle_len)->challenge,
            new_secret->oracle_len * sizeof(uint8_t));
      }
      memcpy(&packedpass_share[j * new_secret->oracle_len], shares[i+1], new_secret->key_len);
    }

    new_secret->pass_shares[i] = SDMCKT_malloc((octlen + share_enc_len) * sizeof(uint8_t));
    if (new_secret->pass_shares[i] == NULL) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }

    /* FIXME: hardcoded magic numbers. */
    scryptret = scryptenc_buf(packedpass_share, octlen + key_len, new_secret->pass_shares[i],
        SDMCKT_authlist_getpass(auth_data, i)->passphrase,
        SDMCKT_authlist_getpass(auth_data, i)->len, 0, 0.25, 2.0);

    if (packedpass_share != shares[i+1]) {
      SDMCKT_free(packedpass_share, octlen + key_len);
    }

    if (scryptret != 0) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      printf("scrypt error!: %d\n", scryptret);
      goto secret_error;
    }
  }

  /* Encrypt oracle shares */
  new_secret->oracle_shares = malloc(new_secret->oracle_num * sizeof(uint8_t **));
  if (new_secret->pass_shares == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  for (i = 0; i < new_secret->oracle_num; i++) {
    new_secret->oracle_shares[i] = SDMCKT_malloc(share_enc_len * sizeof(uint8_t));
    if (new_secret->oracle_shares[i] == NULL) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }

    if (SDMCKT_oracle_query(SDMCKT_authlist_getoracle(auth_data, i)) != 0) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto secret_error;
    }
    /* FIXME: hardcoded magic numbers. */
    scryptret = scryptenc_buf(shares[i + 1 + new_secret->pass_num], key_len,
        new_secret->oracle_shares[i],
        SDMCKT_authlist_getoracle(auth_data, i)->resp,
        SDMCKT_authlist_getoracle(auth_data, i)->resp_len, 0, 0.25, 2.0);
    SDMCKT_oracle_clearresp(SDMCKT_authlist_getoracle(auth_data, i));
    if ( scryptret != 0) {
      err += 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      printf("scrypt error!: %d\n", scryptret);
#endif
      goto secret_error;
    }
  }

  /* Encrypt data */
  new_secret->data = SDMCKT_malloc(data_enc_len * sizeof(uint8_t));
  if (new_secret->data == NULL) {
    err += 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto secret_error;
  }

  /* FIXME: hardcoded magic numbers. */
  err += scryptenc_buf(data, data_len, new_secret->data,
      (*key), new_secret->key_len, 0, 0.25, 2.0);
  if (err != 0) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    printf("scrypt error!: %d\n", scryptret);
#endif
    goto secret_error;
  }

  /* Update checksum */
  SDMCKT_secret_checksum(new_secret);

secret_error:
  if (err > 0) {
    if (new_secret != NULL) {
      SDMCKT_secret_free(new_secret);
      new_secret = NULL;
    }
  }
  if (shares != NULL) {
    for (i = 1; i <= N; i++) {
      if (shares[i] != NULL) {
        SDMCKT_free(shares[i], key_len * sizeof(uint8_t));
      }
    }
  free(shares);
  shares = NULL;
  }

#ifdef DEBUG
  if ( new_secret == NULL) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif

  return new_secret;
}

void SDMCKT_secret_free(SDMCKT_secret * secret) {
  size_t data_enc_len, share_enc_len, i;

  data_enc_len = secret->data_len + secret->scrypt_len + 1;
  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  if (secret->data != NULL) {
    SDMCKT_free(secret->data, data_enc_len * sizeof(uint8_t));
  }
  if (secret->oracle_challenges != NULL) {
    for (i = 0; i < secret->oracle_num; i++) {
      if (secret->oracle_challenges[i] != NULL) {
        SDMCKT_free(secret->oracle_challenges[i],
            (secret->oracle_num * secret->oracle_len) * sizeof(uint8_t));
      }
    }
    free(secret->oracle_challenges);
  }
  if (secret->pass_shares != NULL) {
    if (secret->pass_num == 1) {
      SDMCKT_free(secret->pass_shares[0],
          ((secret->oracle_num * secret->oracle_len) + share_enc_len)
          * sizeof(uint8_t));
    } else {
      for (i = 0; i < secret->pass_num; i++) {
        if (secret->pass_shares[i] != NULL) {
          SDMCKT_free(secret->pass_shares[i], share_enc_len * sizeof(uint8_t));
        }
      }
    }
    free(secret->pass_shares);
  }
  if (secret->oracle_shares != NULL) {
    for (i = 0; i < secret->oracle_num; i++) {
      if (secret->oracle_shares[i] != NULL) {
        SDMCKT_free(secret->oracle_shares[i], share_enc_len * sizeof(uint8_t));
      }
    }
    free(secret->oracle_shares);
  }
  SDMCKT_free(secret, sizeof(SDMCKT_secret));
}

/* FIXME: This should pass through errors. */
void SDMCKT_secret_checksum(SDMCKT_secret * secret) {
  SHA256_CTX s256ctx;
  uint16_t key_len_be = 0;
  uint32_t data_len_be = 0;
  size_t data_enc_len, share_enc_len, i;

  data_enc_len = secret->data_len + secret->scrypt_len + 1;
  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  /* Create checksum */
  SHA256_Init(&s256ctx);
  key_len_be = htons(secret->key_len);
  data_len_be = htonl(secret->data_len);
  SHA256_Update(&s256ctx, &secret->ver, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &secret->scrypt_len, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &key_len_be, sizeof(uint16_t));
  SHA256_Update(&s256ctx, &secret->share_M, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &secret->share_N, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &secret->pass_num, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &secret->oracle_num, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &secret->oracle_len, sizeof(uint8_t));
  SHA256_Update(&s256ctx, &data_len_be, sizeof(uint32_t));
  /* Add challenges if not inside passphrase share. */
  if (secret->pass_num != 1) {
    for (i = 0; i < secret->oracle_num; i++) {
      SHA256_Update(&s256ctx, secret->oracle_challenges[i],
          secret->oracle_len * sizeof(uint8_t));
    }
  }
  for (i = 0; i < secret->pass_num; i++) {
    if (secret->pass_num == 1) {
      SHA256_Update(&s256ctx, secret->pass_shares[i],
          (share_enc_len + (secret->oracle_len * secret->oracle_num))
           * sizeof(uint8_t));
    } else {
      SHA256_Update(&s256ctx, secret->pass_shares[i],
          share_enc_len * sizeof(uint8_t));
    }
  }
  for (i = 0; i < secret->oracle_num; i++) {
    SHA256_Update(&s256ctx, secret->oracle_shares[i],
        share_enc_len * sizeof(uint8_t));
  }
  SHA256_Update(&s256ctx, secret->data, data_enc_len * sizeof(uint8_t));
  SHA256_Final((unsigned char *)&secret->checksum,&s256ctx);
}

uint8_t * SDMCKT_secret_serialize(SDMCKT_secret * secret)
{
  uint8_t * buf = NULL;
  uint16_t key_len_be = 0;
  uint32_t data_len_be = 0;
  size_t data_enc_len, share_enc_len, tsize, i, j = 0;

  data_enc_len = secret->data_len + secret->scrypt_len + 1;
  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  tsize = SDMCKT_secret_mdsize 
    + (share_enc_len * (secret->pass_num + secret->oracle_num))
    + (secret->oracle_len * secret->oracle_num)
    + data_enc_len;

  buf = malloc(tsize * sizeof(uint8_t));
  if ( buf == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    return NULL;
  }

  key_len_be = htons(secret->key_len);
  data_len_be = htonl(secret->data_len);

  memcpy(&buf[j], &secret->ver, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &secret->scrypt_len, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &key_len_be, sizeof(uint16_t));
  j += sizeof(uint16_t);
  memcpy(&buf[j], &secret->share_M, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &secret->share_N, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &secret->pass_num, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &secret->oracle_num, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &secret->oracle_len, sizeof(uint8_t));
  j++;
  memcpy(&buf[j], &data_len_be, sizeof(uint32_t));
  j += sizeof(uint32_t);
  /* Add challenges if not inside passphrase share. */
  if (secret->pass_num != 1) {
    for (i = 0; i < secret->oracle_num; i++) {
      memcpy(&buf[j], secret->oracle_challenges[i],
          secret->oracle_len * sizeof(uint8_t));
      j += secret->oracle_len * sizeof(uint8_t);
    }
  }
  for (i = 0; i < secret->pass_num; i++) {
    if (secret->pass_num == 1) {
      memcpy(&buf[j], secret->pass_shares[i],
          (share_enc_len + (secret->oracle_len * secret->oracle_num))
          * sizeof(uint8_t));
      j += (share_enc_len + (secret->oracle_len * secret->oracle_num))
          * sizeof(uint8_t);
    } else {
      memcpy(&buf[j], secret->pass_shares[i],
          share_enc_len * sizeof(uint8_t));
      j += share_enc_len * sizeof(uint8_t);
    }
  }
  for (i = 0; i < secret->oracle_num; i++) {
    memcpy(&buf[j], secret->oracle_shares[i],
        share_enc_len * sizeof(uint8_t));
    j += share_enc_len * sizeof(uint8_t);
  }
  memcpy(&buf[j], secret->data, data_enc_len * sizeof(uint8_t));
  j += data_enc_len * sizeof(uint8_t);
  memcpy(&buf[j], secret->checksum, SHA256_DIGEST_LENGTH * sizeof(uint8_t));

  return buf;
}

/* Returns the passphrase share and populates the oracle challenges */
uint8_t * SDMCKT_secret_challenges_frompass(SDMCKT_secret * secret,
    SDMCKT_passphrase * pass, uint8_t * enc_pass_share)
{
  size_t i, j = 0, dec_pass_buf_len, dec_bytes;
  int err = 0;
  uint8_t * dec_pass_buf = NULL;
  uint8_t * ret_buf = NULL;

  /* Scrypt decrypt buffer must be same size as encrypted data. */
  dec_pass_buf_len = ((secret->oracle_num * secret->oracle_len)
      + secret->key_len + secret->scrypt_len + 1) * sizeof(uint8_t);

  /* Allocate return buffer */
  ret_buf = SDMCKT_malloc(secret->key_len * sizeof(uint8_t));
  if (ret_buf == NULL) {
    err = 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto cfrompass_error;
  }

  dec_pass_buf = SDMCKT_malloc(dec_pass_buf_len);
  if (dec_pass_buf == NULL) {
    err = 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto cfrompass_error;
  }

  /* FIXME: hardcoded magic numbers. */
  err = scryptdec_buf(enc_pass_share, dec_pass_buf_len, dec_pass_buf, &dec_bytes,
      pass->passphrase, pass->len, 0, 0.25, 600.0);

  if(err != 0 || dec_bytes != dec_pass_buf_len - secret->scrypt_len - 1) {
    if (err == 0) {
      err = 1;
    }
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    printf("scrypt error!: %d\n", err);
#endif
    goto cfrompass_error;
  }

  secret->oracle_challenges = SDMCKT_malloc(secret->oracle_num * sizeof(uint8_t **));
  if (secret->oracle_challenges == NULL) {
    err = 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto cfrompass_error;
  }

  for (i = 0; i < secret->oracle_num; i++) {
    secret->oracle_challenges[i] = SDMCKT_malloc(secret->oracle_len);
    if (secret->oracle_challenges[i] == NULL) {
      err = 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto cfrompass_error;
    }
    memcpy(secret->oracle_challenges[i], &dec_pass_buf[j], secret->oracle_len);
    j += secret->oracle_len;
  }

  memcpy(ret_buf, &dec_pass_buf[j], secret->key_len);

cfrompass_error:
  if (err > 0) {
    if (secret->oracle_challenges != NULL) {
      for (i = 0; i < secret->oracle_num; i++) {
        if (secret->oracle_challenges[i] != NULL) {
          SDMCKT_free(secret->oracle_challenges[i], secret->oracle_len);
          secret->oracle_challenges[i] = NULL;
        }
      }
      free(secret->oracle_challenges);
      secret->oracle_challenges = NULL;
    }
    if (ret_buf != NULL) {
      SDMCKT_free(ret_buf, secret->key_len);
      ret_buf = NULL;
    }
  }

  SDMCKT_free(dec_pass_buf, dec_pass_buf_len);

#ifdef DEBUG
  if ( ret_buf == NULL) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif
  
  return ret_buf;
}

/*
 * After deserialization secret->oracle_challenges will be NULL if pass_num = 1
 * and the passphrase provided to the derserialize function is NULL
 */
SDMCKT_secret * SDMCKT_secret_deserialize(uint8_t * input,
    SDMCKT_passphrase * pass)
{
  SDMCKT_secret * secret = NULL;
  uint16_t key_len_be = 0;
  uint32_t data_len_be = 0;
  size_t data_enc_len, share_enc_len, pass_share_enc_len, tsize;
  size_t i, j = 0, err = 0;
  uint8_t * share_buf;

  secret = SDMCKT_malloc(sizeof(SDMCKT_secret));
  if (secret == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    return NULL;
  }

  secret->ver = input[j];
  j++;
  secret->scrypt_len = input[j];
  j++;
  memcpy(&key_len_be, &input[j], sizeof(uint16_t));
  secret->key_len = ntohs(key_len_be);
  j += sizeof(uint16_t);
  secret->share_M = input[j];
  j++;
  secret->share_N = input[j];
  j++;
  secret->pass_num = input[j];
  j++;
  secret->oracle_num = input[j];
  j++;
  secret->oracle_len = input[j];
  j++;
  memcpy(&data_len_be, &input[j], sizeof(uint32_t));
  secret->data_len = ntohl(data_len_be);
  j += sizeof(uint32_t);

  data_enc_len = secret->data_len + secret->scrypt_len + 1;
  share_enc_len = secret->key_len + secret->scrypt_len + 1;
  if (secret->pass_num == 1) {
    pass_share_enc_len = (share_enc_len + (secret->oracle_len * secret->oracle_num));
  } else {
    pass_share_enc_len = share_enc_len;
  }

  tsize = SDMCKT_secret_mdsize 
    + (share_enc_len * (secret->pass_num + secret->oracle_num))
    + (secret->oracle_len * secret->oracle_num)
    + data_enc_len;

  secret->oracle_challenges = NULL;
  secret->oracle_challenges = calloc(secret->oracle_num, sizeof(uint8_t *));
  if (secret->oracle_challenges == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto deserialize_error;
  }

  if (secret->pass_num == 1) {
    if (pass != NULL) {
      share_buf = SDMCKT_secret_challenges_frompass(secret, pass, &input[j]);
      if (share_buf == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        err = 1;
        goto deserialize_error;
      }
      /* We don't actually need this. */
      SDMCKT_free(share_buf, secret->key_len);
    } else {
      free(secret->oracle_challenges);
      secret->oracle_challenges = NULL;
    }
  } else {
    for (i = 0; i < secret->oracle_num; i++) {
      secret->oracle_challenges[i] = SDMCKT_malloc(secret->oracle_len);
      if (secret->oracle_challenges[i] == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        err = 1;
        goto deserialize_error;
      }
      memcpy(secret->oracle_challenges[i], &input[j], secret->oracle_len);
      j += secret->oracle_len;
    }
  }

  secret->pass_shares = malloc(secret->pass_num * sizeof(uint8_t *));
  if (secret->pass_shares == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto deserialize_error;
  }

  for (i = 0; i < secret->pass_num; i++) {
    secret->pass_shares[i] = SDMCKT_malloc(pass_share_enc_len * sizeof(uint8_t));
    if (secret->pass_shares[i] == NULL) {
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto deserialize_error;
    }
    memcpy(secret->pass_shares[i], &input[j], pass_share_enc_len);
    j += pass_share_enc_len;
  }

  secret->oracle_shares = malloc(secret->oracle_num * sizeof(uint8_t *));
  if (secret->pass_shares == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto deserialize_error;
  }

  for (i = 0; i < secret->oracle_num; i++) {
    secret->oracle_shares[i] = SDMCKT_malloc(share_enc_len * sizeof(uint8_t));
    if (secret->oracle_shares[i] == NULL) {
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto deserialize_error;
    }
    memcpy(secret->oracle_shares[i], &input[j], share_enc_len);
    j += share_enc_len;
  }

  secret->data = SDMCKT_malloc(data_enc_len * sizeof(uint8_t));
  memcpy(secret->data, &input[j], data_enc_len);
  j += data_enc_len * sizeof(uint8_t);

  /* Make sure our checksums line up */
  SDMCKT_secret_checksum(secret);
  if ((memcmp(secret->checksum, &input[j], SHA256_DIGEST_LENGTH) != 0)) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto deserialize_error;
  }

  j += SHA256_DIGEST_LENGTH;
  if (j != tsize) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto deserialize_error;
  }

deserialize_error:
  if (err > 0) {
    SDMCKT_secret_free(secret);
    secret = NULL;
  }

  return secret;
}

int SDMCKT_secret_to_file(FILE * outfile, SDMCKT_secret * secret)
{
  size_t data_enc_len, share_enc_len, tsize, err;
  uint8_t * buf = NULL;

  data_enc_len = secret->data_len + secret->scrypt_len + 1;
  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  tsize = SDMCKT_secret_mdsize 
    + (share_enc_len * (secret->pass_num + secret->oracle_num))
    + (secret->oracle_len * secret->oracle_num)
    + data_enc_len;

  buf = SDMCKT_secret_serialize(secret);

  err = fwrite(buf, sizeof(uint8_t), tsize, outfile);

  SDMCKT_free(buf, tsize);

#ifdef DEBUG
  if (!err) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif
  return err;
}

/* FIXME: this is awful */
SDMCKT_secret * SDMCKT_secret_from_file(FILE * infile, SDMCKT_passphrase * pass)
{
  uint8_t * buf = NULL, * rbuf = NULL;
  size_t buf_sz = 4096, total = 0, i = 0;
  SDMCKT_secret * secret;

  buf = malloc(4096 * sizeof(uint8_t));
  if (buf == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    return NULL;
  }
  while ((i = fread(&buf[total], sizeof(uint8_t), 512, infile))) {
    total += i;
    if (total >= buf_sz - 512) {
      buf_sz += 4096;
      rbuf = realloc(buf, buf_sz);
      if (rbuf == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        free(buf);
        return NULL;
      }
      buf = rbuf;
      rbuf = NULL;
    }
  }
  total += i;

  secret = SDMCKT_secret_deserialize(buf, pass);
  free(buf);
  return secret;
}

uint8_t * SDMCKT_secret_get_key(SDMCKT_secret * secret,
    SDMCKT_authlist * auth_data)
{
  SDMCKT_oracle * tmporacle = NULL;
  SDMCKT_passphrase * tmppass = NULL;
  size_t share_enc_len, i, dec_bytes, err = 0;
  uint8_t ** shares = NULL, * key = NULL, * dec_buf = NULL;

  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  dec_buf = SDMCKT_malloc(share_enc_len * sizeof(uint8_t));
  if (dec_buf == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto getkey_error;
  }

  /* Allocate shares array */
  shares = malloc((secret->share_N + 1) * sizeof(uint8_t **));
  for (i = 0; i < secret->share_N + 1; i++) {
    shares[i] = SDMCKT_malloc(secret->key_len * sizeof(uint8_t));
    if (shares[i] == NULL) {
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto getkey_error;
    }
  }

  /* First we need to make sure we have the oracle challenges. */
  if (secret->pass_num == 1) {
    if (secret->oracle_challenges != NULL) {
      for (i = 0; i < secret->oracle_num; i++) {
        if (secret->oracle_challenges[i] != NULL) {
          SDMCKT_free(secret->oracle_challenges[i], secret->oracle_len);
        }
      }
      free(secret->oracle_challenges);
      secret->oracle_challenges = NULL;
    }
    SDMCKT_free(shares[1], secret->key_len);
    shares[1] = NULL;
    shares[1] = SDMCKT_secret_challenges_frompass(secret,
        SDMCKT_authlist_getpass(auth_data, 0),
        secret->pass_shares[0]);
    if (shares[1] == NULL) {
      /* Wrong passphrase */
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto getkey_error;
    }
  }

  /* Decrypt passphrase shares if more than one */
  if (secret->pass_num > 1) {
    for (i = 0; i < secret->pass_num; i++) {
      tmppass = SDMCKT_authlist_getpass(auth_data, i);
      /* FIXME: hardcoded magic numbers. */
      err = scryptdec_buf(secret->pass_shares[i], share_enc_len, dec_buf, &dec_bytes,
        tmppass->passphrase, tmppass->len, 0, 0.25, 600.0);
      if (err != 0 || dec_bytes != secret->key_len) {
        /* Bad passphrase */
        err = 1;
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        printf("scrypt error!: %zd\n", err);
#endif
        goto getkey_error;
      }
      memcpy(shares[i+1], dec_buf, secret->key_len);
    }
  }

  /* Decrypt oracle shares */
  for (i = 0; i < secret->oracle_num; i++) {
    tmporacle = SDMCKT_authlist_getoracle(auth_data, 0);
    if (tmporacle->len != secret->oracle_len
        || tmporacle->resp_len == 0) {
      /* Malformed struct */
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto getkey_error;
    }
    /* Skip empty oracles */
    if (tmporacle == NULL) {
      continue;
    }
    memcpy(tmporacle->challenge, secret->oracle_challenges[i],
        secret->oracle_len);
    if (SDMCKT_oracle_query(tmporacle) != 0) {
      /* Bad oracle */
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      err = 1;
      goto getkey_error;
    }
    /* FIXME: hardcoded magic numbers */
    err = scryptdec_buf(secret->oracle_shares[i], share_enc_len, dec_buf, &dec_bytes,
        tmporacle->resp, tmporacle->resp_len, 0, 0.25, 600.0);
    if (err != 0 || dec_bytes != secret->key_len) {
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      printf("scrypt error!: %zd\n", err);
#endif
      goto getkey_error;
    }
    SDMCKT_oracle_clearresp(tmporacle);
    memcpy(shares[i + 1 + secret->pass_num], dec_buf, secret->key_len);
  }

  if (shamirs_combine(secret->share_M, secret->share_N, secret->key_len,
        shares) == 0) {
    key = SDMCKT_malloc(secret->key_len * sizeof(uint8_t));
    if (key == NULL) {
      err = 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto getkey_error;
    }
    memcpy(key, shares[0], secret->key_len);
  }

getkey_error:
  /*
   * We don't clean up the auth structure under any circumstances. That is left
   * to the caller!
   */
  if (err != 0) {
    if (key != NULL) {
      SDMCKT_free(key, secret->key_len);
      key = NULL;
    }
  }

  /* Clean up decrypt buffer */
  if (dec_buf != NULL) {
    SDMCKT_free(dec_buf, share_enc_len);
  }
  /* Clean up shares array */
  if (shares != NULL) {
    for (i = 0; i < secret->share_N + 1; i++) {
      if (shares[i] != NULL) {
        SDMCKT_free(shares[i], secret->key_len);
      }
      shares[i] = NULL;
    }
    free(shares);
  }

#ifdef DEBUG
  if (key == NULL) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif

  return key;
}

uint8_t * SDMCKT_secret_get_data(SDMCKT_secret * secret, uint8_t * key)
{
  uint8_t * dec_buf = NULL, * dec_data = NULL;
  size_t dec_bytes, data_enc_len, err = 0;
  int scryptret;

  data_enc_len = secret->data_len + secret->scrypt_len + 1;

  dec_buf = SDMCKT_malloc(data_enc_len * sizeof(uint8_t));
  if (dec_buf == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto getdata_error;
  }

  dec_data = SDMCKT_malloc(secret->data_len * sizeof(uint8_t));
  if (dec_data == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto getdata_error;
  }

  /* FIXME: hardcoded magic numbers. */
  scryptret = scryptdec_buf(secret->data, data_enc_len, dec_buf, &dec_bytes,
      key, secret->key_len, 0, 0.25, 600.0);

  if (scryptret != 0 || dec_bytes != secret->data_len) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    printf("scrypt error!: %d\n", scryptret);
#endif
    err = 1;
    goto getdata_error;
  }

  memcpy(dec_data, dec_buf, secret->data_len);

getdata_error:
  if (err != 0) {
    if (dec_data != NULL) {
      SDMCKT_free(dec_data, secret->data_len);
      dec_data = NULL;
    }
  }

  if (dec_buf != NULL) {
    SDMCKT_free(dec_buf, data_enc_len);
  }

#ifdef DEBUG
  if ( dec_data == NULL) {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif

  return dec_data;
}

int SDMCKT_secret_replace_data(SDMCKT_secret * secret, uint8_t * key,
    uint32_t data_len, uint8_t * data)
{
  uint8_t * enc_buf = NULL;
  size_t data_enc_len;
  int err = 0;

  data_enc_len = data_len + secret->scrypt_len + 1;

  enc_buf = SDMCKT_malloc(data_enc_len * sizeof(uint8_t));
  if (enc_buf == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    err = 1;
    goto rdata_error;
  }

  /* FIXME: hardcoded magic numbers. */
  err = scryptenc_buf(data, data_len, enc_buf, key, secret->key_len,
      0, 0.25, 2.0);
  if (err != 0) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    printf("scrypt error!: %d\n", err);
#endif
    goto rdata_error;
  }

  if (data_len != secret->data_len) {
    SDMCKT_free(secret->data, secret->data_len);
    secret->data = SDMCKT_malloc(data_enc_len * sizeof(uint8_t));
    if (secret->data == NULL) {
      err = 1;
#ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
      goto rdata_error;
    }
    memcpy(secret->data, enc_buf, data_enc_len);
    secret->data_len = data_len;

    /* Update the checksum */
    SDMCKT_secret_checksum(secret);
  }

rdata_error:
  if (enc_buf != NULL) {
    SDMCKT_free(enc_buf, data_enc_len);
  }

  return err;
}

/* TODO: Test this. */
int SDMCKT_secret_uc_replace_data(uint8_t * secretustr, uint8_t * key,
    uint32_t data_len, uint8_t * data)
{
  SDMCKT_secret * secret;
  size_t share_enc_len, data_off;
  int err = 0;

  secret = SDMCKT_secret_deserialize(secretustr, NULL);
  if (secret == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    return 1;
  }

  err = SDMCKT_secret_replace_data(secret, key, data_len, data);

  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  data_off = SDMCKT_secret_hsize
    + (share_enc_len * (secret->pass_num + secret->oracle_num))
    + (secret->oracle_len * secret->oracle_num) - 1;

  if (err == 0) {
    memcpy(&secretustr[data_off], secret->data, secret->data_len);
    memcpy(&secretustr[data_off + secret->data_len], secret->checksum,
        SHA256_DIGEST_LENGTH);
  }
#ifdef DEBUG
  else {
    SDMCKT_debug_tracking(__FILE__,__LINE__);
  }
#endif

  if (secret != NULL) {
    SDMCKT_secret_free(secret);
  }

  return err;
}

/* FIXME: CODE DUP CODE DUP CODE DUP */
int SDMCKT_secret_replace_share(SDMCKT_secret * secret, uint8_t num,
    SDMCKT_auth * old_auth_data, SDMCKT_auth * new_auth_data,
    SDMCKT_passphrase * pass)
{
  int err = 0;
  uint8_t * dec_buf = NULL, * enc_buf = NULL, * share_buf = NULL;
  uint8_t * packedpass_share = NULL, * packedpass_enc_buf = NULL;
  size_t packedpass_len, pass_share_enc_len, share_enc_len, dec_bytes, i;
  SDMCKT_oracle * oldoracle = NULL, * neworacle = NULL;
  SDMCKT_passphrase * oldpass = NULL, * newpass = NULL;

  share_enc_len = secret->key_len + secret->scrypt_len + 1;

  if (secret->pass_num == 1) {
    pass_share_enc_len = (secret->oracle_num * secret->oracle_len)
      + share_enc_len;
  } else {
    pass_share_enc_len = share_enc_len;
  }

  packedpass_len = secret->key_len + (secret->oracle_num * secret->oracle_len);

  switch (old_auth_data->generic.type) {
    case ORACLE_AUTH:
      dec_buf = SDMCKT_malloc(share_enc_len);
      if (dec_buf == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        err = 1;
        goto rshare_error;
      }
      enc_buf = SDMCKT_malloc(share_enc_len);
      if (enc_buf == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        err = 1;
        goto rshare_error;
      }
      break;
    case PASS_AUTH:
      dec_buf = SDMCKT_malloc(pass_share_enc_len);
      if (dec_buf == NULL) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        err = 1;
        goto rshare_error;
      }
      enc_buf = SDMCKT_malloc(pass_share_enc_len);
      if (enc_buf == NULL) {
        err = 1;
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        goto rshare_error;
      }
      break;
    default:
      break;
  }

  switch (old_auth_data->generic.type) {
    case ORACLE_AUTH:
      if (secret->pass_num == 1) {
        if (pass == NULL) {
#ifdef DEBUG
          SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
          err = 1;
          goto rshare_error;
        }
        /* Overwrite secret->oracle_challenges with stored values. */
        if (secret->oracle_challenges != NULL) {
          for (i = 0; i < secret->oracle_num; i++) {
            if (secret->oracle_challenges[i] != NULL) {
              SDMCKT_free(secret->oracle_challenges[i], secret->oracle_len);
            }
          }
          free(secret->oracle_challenges);
          secret->oracle_challenges = NULL;
        }
        share_buf = SDMCKT_secret_challenges_frompass(secret, pass,
            secret->pass_shares[0]);
        if (share_buf == NULL) {
          err = 1;
#ifdef DEBUG
          SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
          goto rshare_error;
        }
      }
      oldoracle = &old_auth_data->oracle;
      neworacle = &new_auth_data->oracle;
      if (SDMCKT_oracle_query(oldoracle) != 0) {
        err = 1;
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        goto rshare_error;
      }
      /* FIXME: hardcoded magic numbers. */
      err = scryptdec_buf(secret->oracle_shares[num], share_enc_len, dec_buf,
          &dec_bytes, oldoracle->resp, oldoracle->resp_len, 0, 0.25, 600.0);
      SDMCKT_oracle_clearresp(oldoracle);
      if (err != 0 || dec_bytes != secret->key_len) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        printf("scrypt error!: %d\n", err);
#endif
        goto rshare_error;
      }
      if (secret->pass_num == 1) {
        packedpass_share = SDMCKT_malloc(packedpass_len * sizeof(uint8_t));
        if (packedpass_share == NULL) {
          err = 1;
#ifdef DEBUG
          SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
          goto rshare_error;
        }
        for (i = 0; i < secret->oracle_num; i++) {
          if (i != num) {
            memcpy(&packedpass_share[i * secret->oracle_len],
                secret->oracle_challenges[i], secret->oracle_len);
          }
        }
        memcpy(&packedpass_share[num * secret->oracle_len],
            neworacle->challenge, secret->oracle_len);
        memcpy(secret->oracle_challenges[num], neworacle->challenge,
            secret->oracle_len);
        memcpy(&packedpass_share[i * secret->oracle_len],
            share_buf, secret->key_len);
        packedpass_enc_buf = SDMCKT_malloc(pass_share_enc_len * sizeof(uint8_t));
        if (packedpass_enc_buf == NULL) {
          err = 1;
#ifdef DEBUG
          SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
          goto rshare_error;
        }
        /* FIXME: hardcoded magic numbers. */
        err = scryptenc_buf(packedpass_share, packedpass_len, packedpass_enc_buf,
            pass->passphrase, pass->len, 0, 0.25, 2.0);
        if (err != 0) {
#ifdef DEBUG
          SDMCKT_debug_tracking(__FILE__,__LINE__);
          printf("scrypt error!: %d\n", err);
#endif
          goto rshare_error;
        }
        memcpy(secret->pass_shares[0], packedpass_enc_buf, pass_share_enc_len);
      }
      if (SDMCKT_oracle_query(neworacle) != 0) {
        err = 1;
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
        goto rshare_error;
      }
      /* FIXME: hardcoded magic numbers. */
      err = scryptenc_buf(dec_buf, secret->key_len, enc_buf, neworacle->resp,
          neworacle->resp_len, 0, 0.25, 2.0);
      SDMCKT_oracle_clearresp(neworacle);
      if (err != 0) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        printf("scrypt error!: %d\n", err);
#endif
        goto rshare_error;
      }
      memcpy(secret->oracle_shares[num], enc_buf, share_enc_len);
      memcpy(secret->oracle_challenges[num], neworacle->challenge,
          secret->oracle_len);
      break;
    case PASS_AUTH:
      oldpass = &old_auth_data->pass;
      newpass = &new_auth_data->pass;
      /* FIXME: hardcoded magic numbers. */
      err = scryptdec_buf(secret->pass_shares[num], pass_share_enc_len, dec_buf,
          &dec_bytes, oldpass->passphrase, oldpass->len, 0, 0.25, 600.0);
      if (err != 0 || dec_bytes != packedpass_len) {
        if (err == 0) {
          err = 1;
        }
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        printf("scrypt error!: %d\n", err);
#endif
        goto rshare_error;
      }
      /* FIXME: hardcoded magic numbers. */
      err = scryptenc_buf(dec_buf, packedpass_len, enc_buf, newpass->passphrase,
          newpass->len, 0, 0.25, 2.0);
      if (err != 0) {
#ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        printf("scrypt error!: %d\n", err);
#endif
        goto rshare_error;
      }
      memcpy(secret->pass_shares[num], enc_buf, pass_share_enc_len);
      break;
     default:
      break;
  }

  /* Update the checksum */
  SDMCKT_secret_checksum(secret);

rshare_error:
  if (packedpass_share != NULL) {
    SDMCKT_free(packedpass_share, packedpass_len);
  }
  if (packedpass_enc_buf != NULL) {
    SDMCKT_free(packedpass_enc_buf, pass_share_enc_len);
  }
  if (share_buf != NULL) {
    SDMCKT_free(share_buf, secret->key_len);
  }
  switch (old_auth_data->generic.type) {
    case ORACLE_AUTH:
      if (dec_buf != NULL) {
        SDMCKT_free(dec_buf, share_enc_len);
      }
      if (enc_buf != NULL) {
        SDMCKT_free(enc_buf, share_enc_len);
      }
      break;
    case PASS_AUTH:
      if (dec_buf != NULL) {
        SDMCKT_free(dec_buf, pass_share_enc_len);
      }
      if (enc_buf != NULL) {
        SDMCKT_free(enc_buf, pass_share_enc_len);
      }
      break;
    default:
      break;
  }

  return err;
}

/* TODO: Test this. */
int SDMCKT_secret_uc_replace_share(uint8_t * secretustr, uint8_t num,
    SDMCKT_auth * old_auth_data, SDMCKT_auth * new_auth_data,
    SDMCKT_passphrase * pass)
{
  SDMCKT_secret * secret = NULL;
  size_t pass_share_enc_len, share_enc_len, data_enc_len, share_off, check_off;
  int err = 0;

  secret = SDMCKT_secret_deserialize(secretustr, pass);
  if (secret == NULL) {
    err = 1;
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto ucrshare_error;
  }
  err = SDMCKT_secret_replace_share(secret, num, old_auth_data,
      new_auth_data, pass);
  if (err != 0) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto ucrshare_error;
  }

  share_enc_len = secret->key_len + secret->scrypt_len + 1;
  data_enc_len = secret->data_len + secret->scrypt_len + 1;

  switch (old_auth_data->generic.type) {
    case ORACLE_AUTH:
      share_off = SDMCKT_secret_hsize
        + (secret->oracle_len * secret->oracle_num)
        + (share_enc_len * (secret->oracle_num - num));
      memcpy(&secretustr[share_off], secret->oracle_shares[num], share_enc_len);
      break;
    case PASS_AUTH:
      share_off = SDMCKT_secret_hsize
        + (share_enc_len * (secret->pass_num - num));
      if (secret->pass_num > 1) {
        share_off += secret->oracle_len * secret->oracle_num;
        pass_share_enc_len = share_enc_len;
      } else {
        pass_share_enc_len = (secret->oracle_num * secret->oracle_len)
          + share_enc_len;
      }
      memcpy(&secretustr[share_off], secret->pass_shares[num], pass_share_enc_len);
      break;
    default:
      break;
  }

  check_off = SDMCKT_secret_hsize
    + (share_enc_len * (secret->pass_num + secret->oracle_num))
    + (secret->oracle_len * secret->oracle_num) - 1
    + data_enc_len;

  memcpy(&secretustr[check_off], secret->checksum, SHA256_DIGEST_LENGTH);

ucrshare_error:
  return err;
}

SDMCKT_secret * SDMCKT_secret_resplit(SDMCKT_secret * secret, SDMCKT_authlist * oldauth,
    SDMCKT_authlist * newauth) {
  SDMCKT_secret * new_secret = NULL;
  uint8_t ** key = NULL;
  uint8_t * data = NULL;

  key = calloc(1, sizeof(uint8_t *));
  if (key == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto resplit_error;
  }

  (*key) = SDMCKT_secret_get_key(secret, oldauth);
  if ((*key) == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto resplit_error;
  }

  data = SDMCKT_secret_get_data(secret, (*key));
  if (data == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto resplit_error;
  }

  new_secret = SDMCKT_secret_new(key, secret->key_len, secret->share_N,
      secret->data_len, data, newauth);
  if (new_secret == NULL) {
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto resplit_error;
  }

resplit_error:
  if (key != NULL) {
    if ((*key) != NULL) {
      SDMCKT_free((*key), secret->key_len);
    }
    free(key);
  }

  if (data != NULL) {
    SDMCKT_free(data, secret->data_len);
  }

  return new_secret;
}

