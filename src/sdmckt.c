#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "readpass.h"
#include "sdmckt0/util.h"
#include "sdmckt0/auth.h"
#include "sdmckt0/secret.h"
#include "sdmckt0/oracle_yubikey.h"

int main(int argc, char **argv) {
  int create_flag = 0, save_flag = 0, verbose_flag = 0, noop_flag = 0, pass_flag = 0;
  char * src_fname = NULL, * dst_fname = NULL;
  FILE * fsrc = NULL, * fdst = NULL;
  uint8_t ** key = NULL;
  uint8_t ** passphrase = NULL;
  size_t key_len = 0;
  int opt, i;
  SDMCKT_secret * secret_src = NULL, * secret_dst = NULL;
  SDMCKT_authlist * authi = NULL, * autho = NULL;

  errno = 0;

  key = malloc(sizeof(uint8_t *));
  if (key == NULL) {
    #ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    #endif
    perror("malloc");
    exit(2);
  }
  (*key) = NULL;

  passphrase = malloc(sizeof(uint8_t *));
  if (passphrase == NULL) {
    #ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    #endif
    perror("malloc");
    exit(2);
  }
  (*passphrase) = NULL;

  while ((opt = getopt(argc, argv, "chvi:o:snpK:")) != -1) {
    switch (opt) {
      /* Create key */
      case 'c':
        create_flag = 1;
        break;

      /* Help */
      case 'h':
        break;

      /* Verbose */
      case 'v':
        verbose_flag += 1;
        break;

      /* In file */
      case 'i':
        src_fname = optarg;
        break;

      /* Out File */
      case 'o':
        dst_fname = optarg;
        break;

      /* reSplit/Save file? */
      case 's':
        save_flag = 1;
        break;

      /* No-op. Do not overwrite or create anything. Still performs all cryptographic and randomness gathering. */
      case 'n':
        noop_flag = 1;
        break;

      /* Change passphrase */
      case 'p':
        pass_flag = 1;
        break;

      /* Key size */
      case 'K':
        key_len = atoi(optarg);
        break;

      default:
        printf("Invalid arguments!\n");
        exit(1);
        break;
    }
  }

  if (src_fname) {
    fsrc = fopen(src_fname, "r");
  }
  if (dst_fname) {
    if (noop_flag)
      fdst = (FILE*)1;
    else
      fdst = fopen(dst_fname, "w");
  }

  authi = SDMCKT_authlist_new(1, 1);
  autho = SDMCKT_authlist_new(1, 1);

  if (authi == NULL || autho == NULL) {
    #ifdef DEBUG
    SDMCKT_debug_tracking(__FILE__,__LINE__);
    #endif
    perror("create auth");
    exit(3);
  }

  /* -c -K 64 -o newfile */
  if (create_flag) {
    if ( !key_len  || !dst_fname || !fdst) {
        #ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        #endif
      perror("invalid options");
      exit(7);
    }
    tarsnap_readpass((char **)passphrase,"once","twice",1);

    if ((SDMCKT_authlist_add_new(authi, 0, PASS_AUTH, strlen((char *)(*passphrase)),
          (*passphrase)) != 0)
        ||
        (SDMCKT_authlist_add_new(authi, 0, ORACLE_AUTH, 32, NULL, 20,
            &yubikey_oracle_query_slot2) != 0)
        ||
        (SDMCKT_authlist_add_new(autho, 0, PASS_AUTH, strlen((char *)(*passphrase)),
          (*passphrase)) != 0)
        ||
        (SDMCKT_authlist_add_new(autho, 0, ORACLE_AUTH, 32, NULL, 20,
            &yubikey_oracle_query_slot2) != 0)
         ) {
      #ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      #endif
      perror("add auth");
      exit(4);
    }

    secret_dst = SDMCKT_secret_new(key, key_len, 2, 0, NULL, authi);
    if (secret_dst == NULL) {
      #ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      #endif
      perror("encrypt secret");
      exit(5);
    }

    if (!noop_flag) {
      if (SDMCKT_secret_to_file(fdst, secret_dst) == 0) {
        #ifdef DEBUG
        SDMCKT_debug_tracking(__FILE__,__LINE__);
        #endif
        perror("write file");
        exit(6);
      }

      printf("created new key in %s!\n", dst_fname);
    }

    #ifdef DEBUG
    printf("key: ");
    for(i = 0; i < secret_dst->key_len; i++) {
      printf("%02x",(*key)[i]);
    }
    putchar('\n');
    #endif

    fflush(stdout);
  }
  /* -i keyfile */
  else if (src_fname && fsrc) {
    tarsnap_readpass((char **)passphrase,"pass",NULL,1);

    if (
        (SDMCKT_authlist_add_new(authi, 0, PASS_AUTH, strlen((char *)(*passphrase)),
          (*passphrase)) != 0)
        ||
        (SDMCKT_authlist_add_new(autho, 0, PASS_AUTH, strlen((char *)(*passphrase)),
          (*passphrase)) != 0)
         ) {
      #ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      #endif
      perror("add auth");
      exit(4);
    }

    secret_src = SDMCKT_secret_from_file(fsrc, SDMCKT_authlist_getpass(authi, 0));
    if (secret_src == NULL) {
      fprintf(stderr,"deserialize error\n");
      exit(5);
    }

    if (
        (SDMCKT_authlist_add_new(authi, 0, ORACLE_AUTH, 32, secret_src->oracle_challenges[0], 20,
            &yubikey_oracle_query_slot2) != 0)
        ||
        (SDMCKT_authlist_add_new(autho, 0, ORACLE_AUTH, 32, NULL, 20,
            &yubikey_oracle_query_slot2) != 0)
       ) {
      #ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      #endif
      perror("add auth");
      exit(4);
    }

    (*key) = SDMCKT_secret_get_key(secret_src, authi);
    if ((*key) == NULL) {
      #ifdef DEBUG
      SDMCKT_debug_tracking(__FILE__,__LINE__);
      #endif
      perror("error reconstructing key");
      exit(6);
    }

    /* FIXME: Not Implemented! */
    /* Change passphrase */
    /* -p -i keyfile */
    if (!noop_flag && pass_flag) {
      printf("Not implemented!\n");
    }
    else if(!noop_flag) {
      for(i = 0; i <secret_src->key_len; i++) {
        printf("%02x",(*key)[i]);
      }
      putchar('\n');
      fflush(stdout);
    }

    /* FIXME: Not Implemented! */
    /* Resplit file after opening */
    /* -s -i keyfile */
    if (!noop_flag && !pass_flag && save_flag) {
      printf("Not implemented!\n");
    }

  }

  return 0;
}

