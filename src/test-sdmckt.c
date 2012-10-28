#include <stdio.h>
#include <unistd.h>

#include "sdmckt0/util.h"
#include "sdmckt0/auth.h"
#include "sdmckt0/secret.h"
#include "sdmckt0/oracle_yubikey.h"

void print_partial(char * s) {
  printf("%s",s);
  fflush(stdout);
}

void print_dot(void) {
  putchar('.');
  fflush(stdout);
}

void print_result(char * s) {
  printf("%s\n",s);
  fflush(stdout);
}

void print_success(void) {
  print_result("success!");
}

void print_failure(void) {
  print_result("failure!");
}

int main(int argc, char **argv)
{
  SDMCKT_authlist * auth = NULL, * auth2 = NULL;
  SDMCKT_secret * secret = NULL, * secret2 = NULL, * secret3 = NULL;
  const char * data = "test data";
  const char * data2 = "test2 data2";
  uint8_t ** key = NULL, * rkey = NULL;
  uint8_t * rdata = NULL;
  int tmpret = 0;
  FILE * file;

  key = malloc(sizeof(uint8_t **));
  if (key == NULL) {
    puts("Could not allocate memory for key!");
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  (*key) = NULL;

  /* Create auth structure */
  print_partial("Creating auth structures.");
  auth = SDMCKT_authlist_new(1, 1);
  print_dot();
  auth2 = SDMCKT_authlist_new(1, 1);
  print_dot();
  if (auth == NULL || auth2 == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to add passphrase to auth.");
  tmpret = SDMCKT_authlist_add_new(auth, 0, PASS_AUTH, 4, "whoa");
  print_dot();
  if (tmpret != 0 ) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_partial("Attempting to add oracle to auth.");
  tmpret = SDMCKT_authlist_add_new(auth, 0, ORACLE_AUTH, 32, NULL, 20,
      &yubikey_oracle_query_slot2);
  print_dot();
  if (tmpret != 0 ) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to add passphrase to auth2.");
  tmpret = SDMCKT_authlist_add_new(auth2, 0, PASS_AUTH, 5, "whoa2");
  print_dot();
  if (tmpret != 0 ) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_partial("Attempting to add oracle to auth2.");
  tmpret = SDMCKT_authlist_add_new(auth2, 0, ORACLE_AUTH, 32, NULL, 20,
      &yubikey_oracle_query_slot2);
  print_dot();
  if (tmpret != 0 ) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  /* Create secret with random key */
  print_partial("Creating secret structure with random key.");
  secret = SDMCKT_secret_new(key, 64, 2, strlen(data), (uint8_t *) data, auth);
  print_dot();
  if (secret == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  /* serialize to file */
  print_partial("Attempting to open testfile for writing.");
  file = fopen("testfile", "w");
  print_dot();
  if (file == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_partial("Attempting to write secret structure to testfile.");
  tmpret = SDMCKT_secret_to_file(file, secret);
  print_dot();
  if (tmpret == 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_result("Closing testfile.");
  fclose(file);

  /* deserialize from file */
  print_partial("Attempting to open testfile for reading.");
  file = fopen("testfile", "r");
  print_dot();
  if (file == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_partial("Attempting to read secret structure from testfile.");
  secret2 = SDMCKT_secret_from_file(file, NULL);
  print_dot();
  if (secret2 == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();
  print_result("Closing testfile.");
  fclose(file);

  print_partial("Attempting to get key.");
  rkey = SDMCKT_secret_get_key(secret2, auth);
  print_dot();
  if (rkey == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to recombine key.");
  tmpret = memcmp((*key), rkey, secret2->key_len);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to get data.");
  rdata = SDMCKT_secret_get_data(secret2, rkey);
  print_dot();
  if (rdata == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Comparing data with expected value.");
  tmpret = memcmp(rdata, data, secret2->data_len);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  SDMCKT_free(rdata, secret2->data_len);
  rdata = NULL;

  print_partial("Attempting to replace data.");
  tmpret = SDMCKT_secret_replace_data(secret2, rkey, strlen(data2),
        (uint8_t *) data2);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to get replaced data.");
  rdata = SDMCKT_secret_get_data(secret2, rkey);
  print_dot();
  if (rdata == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Comparing data2 with expected value.");
  tmpret = memcmp(rdata, data2, secret2->data_len);
  print_dot();
  if (tmpret  != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to replace oracle auth share.");
  tmpret = SDMCKT_secret_replace_share(secret2, 0,
      SDMCKT_authlist_getoracle_union(auth, 0),
      SDMCKT_authlist_getoracle_union(auth2, 0),
      SDMCKT_authlist_getpass(auth, 0));
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to replace passphrase auth share.");
  tmpret = SDMCKT_secret_replace_share(secret2, 0,
      SDMCKT_authlist_getpass_union(auth, 0),
      SDMCKT_authlist_getpass_union(auth2, 0),
      NULL);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  SDMCKT_free(rkey,secret2->key_len);
  rkey = NULL;

  print_partial("Attempting to get key with new auth data.");
  rkey = SDMCKT_secret_get_key(secret2, auth2);
  print_dot();
  if (rkey == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Comparing retrieved rkey with key.");
  tmpret = memcmp((*key), rkey, secret2->key_len);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Attempting to resplit secret2 into secret3.");
  secret3 = SDMCKT_secret_resplit(secret2, auth2, auth);
  print_dot();
  if (secret3 == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  SDMCKT_free(rkey,secret2->key_len);
  rkey = NULL;

  print_partial("Attempting to get key from resplit secret3.");
  rkey = SDMCKT_secret_get_key(secret3, auth);
  print_dot();
  if (rkey == NULL) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();

  print_partial("Comparing retrieved rkey with key.");
  tmpret = memcmp((*key), rkey, secret3->key_len);
  print_dot();
  if (tmpret != 0) {
    print_failure();
#ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
#endif
    goto error;
  }
  print_success();


error:
  fflush(stdout);

  if (secret2 != NULL) {
    if (key != NULL) {
      if ((*key) != NULL) {
        SDMCKT_free((*key), secret2->key_len);
        (*key) = NULL;
      }
      free(key);
      key = NULL;
    }
    if (rkey != NULL) {
      SDMCKT_free(rkey, secret2->key_len);
      rkey = NULL;
    }

    if (rdata != NULL) {
      SDMCKT_free(rdata, secret2->data_len);
      rdata = NULL;
    }
    SDMCKT_secret_free(secret2);
    secret2 = NULL;
  }

  if (secret != NULL) {
    SDMCKT_secret_free(secret);
    secret = NULL;
  }

  if (secret3 != NULL) {
    SDMCKT_secret_free(secret3);
  }

  if (auth != NULL) {
    SDMCKT_authlist_free(auth);
    auth = NULL;
  }

  if (auth2 != NULL) {
    SDMCKT_authlist_free(auth2);
    auth2 = NULL;
  }

  unlink("testfile");

  return tmpret;
}
