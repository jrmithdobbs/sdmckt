#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "shamirs_constants.h"

typedef struct shamirs_state {
  /* Number of input points and output points */
  int in_num;
  int out_num;
  /* Input and output points */
  unsigned char in_points[256];
  unsigned char out_points[256];
  /* Product of the (xi-xj) with j not equal to i, where xi are input points */
  unsigned char in_cross[256];
  /* Product of the (zi-xj) where zi are output points and xj are input points */
  unsigned char out_cross[256];
  /* Input and output values */
  unsigned char in_data[256];
  unsigned char out_data[256];
} shamirs_state;

/* Compute the previous table. */
void shamirs_precalc(shamirs_state *state)
{
  int i, j;
  unsigned char n;

  for ( i=0 ; i<(*state).in_num ; i++ ) {
    n = 1;
    for ( j=0 ; j<(*state).in_num ; j++ )
      if ( j != i )
        n = conmul_tab[n][((*state).in_points[i])^((*state).in_points[j])];
    (*state).in_cross[i] = n;
  }
  for ( i=0 ; i<(*state).out_num ; i++ ) {
    n = 1;
    for ( j=0 ; j<(*state).in_num ; j++ )
      n = conmul_tab[n][((*state).out_points[i])^((*state).in_points[j])];
    (*state).out_cross[i] = n;
  }
}

/* Process one byte from all inputs */
void shamirs_do_point(shamirs_state * state)
{
  int i, j;
  unsigned char n;

  for ( i=0 ; i<(*state).out_num ; i++ ) {
    n = 0;
    if ( ! (*state).out_cross[i] ) { /* Output point is an input point */
      for ( j=0 ; j<(*state).in_num ; j++ )
        if ( (*state).out_points[i] == (*state).in_points[j] )
          n = (*state).in_data[j];
    } else
      for ( j=0 ; j<(*state).in_num ; j++ )
        n^=conmul_tab[(*state).in_data[j]]
            [conmul_tab[(*state).out_cross[i]]
              [coninv_tab
                [conmul_tab[(*state).in_cross[j]]
                  [
                    ((*state).out_points[i])^((*state).in_points[j])
                  ]
                ]
              ]
            ];
    (*state).out_data[i] = n;
  }
}

#ifdef SHAMIRS_STANDALONE
void error(const char *errmsg)
{
  fprintf (stderr, "%s\n", errmsg);
  exit (EXIT_FAILURE);
}

int shamirs_from_files(int argc, const char **argv)
{
  int k;
  /* Input and output file names */
  const char *in_fn[256];
  const char *out_fn[256];
  /* Input and output streams */
  FILE *in_f[256];
  FILE *out_f[256];
  shamirs_state state;

  state.in_num = 0;
  state.out_num = 0;

  /* Read command line arguments */
  for ( k=1 ; k<argc ; k++ ) {
    int l, p;

    p = 0;
    for ( l=0 ; argv[k][l]>='0' && argv[k][l]<='9' ; l++ ) {
      p = p*10 + (argv[k][l]-'0');
      if ( p >= 256 )
        error ("Point value too large.");
    }

    if ( argv[k][l] == '-' ) {
      int m;

      for ( m=0 ; m<state.in_num ; m++ )
        if ( state.in_points[m] == p )
          error ("Duplicate input point.");
      state.in_points[state.in_num] = p;
      in_fn[state.in_num] = argv[k]+l+1;
      in_f[state.in_num] = fopen (in_fn[state.in_num], "r");
      if ( ! in_f[state.in_num] )
        error ("Failed to open input file.");
      state.in_num++;
    } else if ( argv[k][l] == '+' ) {
      if ( state.out_num >= 256 )
        error ("Too many output points.");
      state.out_points[state.out_num] = p;
      out_fn[state.out_num] = argv[k]+l+1;
      out_f[state.out_num] = fopen (out_fn[state.out_num], "w");
      if ( ! out_f[state.out_num] )
        error ("Failed to open input file.");
      state.out_num++;
    } else
      error ("Bad argument syntax.");
  }

  if ( ! state.in_num )
    error ("No input files.");
  if ( ! state.out_num )
    error ("No output files.");

  shamirs_precalc(&state);

  /* Process data */
  while ( 1 ) {
    for ( k=0 ; k<state.in_num ; k++ ) {
      int ch;

      ch = getc (in_f[k]);
      if ( ch == EOF )
        exit (EXIT_SUCCESS);
      state.in_data[k] = ch;
    }
    shamirs_do_point(&state);
    for ( k=0 ; k<state.out_num ; k++ )
      putc (state.out_data[k], out_f[k]);
  }

  return 0;  /* Never reached */
}
#endif

/*
 Apply Shamir's Secret Sharing algorithm.
 M = Number of shares necessary to recombine.
 N = Number of shares to create. (0 on recombine. Must be >=2 for split.)
 datalen = size of each share/data
 sharemax = number of unsigned char*'s in shares (Should be N+1 for splitting.)
 shares = array of buffers for created shares. The 0 indexed item should be the source.
  The index of the shares array is significant. If a share is returned as index 1 it should
  be passed back in as index 1. If recombining secrets split where M<N any missing secrets
  should be set to NULL and will be skipped.
 random_dev_path = filesystem path to the random device ("/dev/random" suggested)
 All memory management is left to the caller.
 Return values:
  0 == Success.
  1 == Invalid M/N values.
  2 == cannot open random device (perror will be called)
  3 == Not enough shares for recombination.
*/
int shamirs(unsigned char M, unsigned char N,
    unsigned char sharemax, size_t datalen, unsigned char ** shares,
    const char * random_dev_path)
{
  FILE * random_dev = NULL;
  shamirs_state state;
  int i,k;

  errno = 0;

  /* Setup state */
  if (M < 2 || N == 1) {
    return 1;
  /* Split */
  } else if (N > 0) {
    state.in_num = M;
    state.out_num = N;
    random_dev = fopen(random_dev_path, "r");

    if (random_dev == NULL) {
      perror("Problem opening random device: ");
      return 2;
    }

    state.in_points[0] = 0;
    for (i = 1; i < M; i++) {
      state.in_points[i] = i;
    }
    for (i = 0;i < N; i++) {
      state.out_points[i] = i+1;
    }
  /* Recombine */
  } else {
    state.in_num = M;
    state.out_num = 1;

    k = 1;
    for (i = 0; i < M && k < sharemax; i++,k++) {
      while (shares[k] == NULL && k < sharemax) k++;
      /* We don't have enough shares! */
      if ( k == sharemax ) return 3;
      state.in_points[i] = k;
    }
    state.out_points[0] = 0;
  }
  shamirs_precalc(&state);

  /* Process data */
  for (i = 0; i < datalen; i++) {
    for (k = 0 ; k < state.in_num ; k++) {
      if ((N > 0 && k == 0)) {
        state.in_data[k] = shares[k][i];
      } else if (N == 0) {
        state.in_data[k] = shares[state.in_points[k]][i];
      } else {
        state.in_data[k] = fgetc(random_dev);
      }
    }
    shamirs_do_point(&state);
    if (N > 0) {
      for (k=0 ; k<state.out_num ; k++) {
          shares[k+1][i] = state.out_data[k];
      }
      } else {
        shares[0][i] = state.out_data[0];
    }
  }

  if(random_dev != NULL) {
    fclose(random_dev);
  }

  return 0;
}

int shamirs_split(unsigned char M, unsigned char N,
    size_t datalen, unsigned char ** shares,
    const char * random_dev_path) {
  return shamirs(M,N,N+1,datalen,shares,random_dev_path);
}

int shamirs_combine(unsigned char M, unsigned char N,
    size_t datalen, unsigned char ** shares ) {
  return shamirs(M,0,N+1,datalen,shares,NULL);
}

#ifdef TEST_SHAMIRS
int test_shamirs(void) {
  unsigned char ** testshares = NULL;
  int i;

  testshares = calloc(3,sizeof(unsigned char*));
  for (i = 0; i < 3; i++) {
    testshares[i] = calloc(5, sizeof(unsigned char));
  }
  testshares[0][0] = 'h';
  testshares[0][1] = 'e';
  testshares[0][2] = 'y';
  testshares[0][3] = 'u';

  puts((const char *)testshares[0]);
  if (!shamirs_split(2,2,4,testshares,"/dev/random")) {
    testshares[0][0] = '\0';
    testshares[0][1] = '\0';
    testshares[0][2] = '\0';
    testshares[0][3] = '\0';
    if (!shamirs_combine(2,2,4,testshares)) {
      puts((const char *)testshares[0]);
    }
  }

  for (i = 0; i < 3; i++) {
    free(testshares[i]);
    testshares[i] = NULL;
  }
  free(testshares);
  testshares = NULL;

  testshares = calloc(4,sizeof(unsigned char*));
  for (i = 0; i < 4; i++) {
    testshares[i] = calloc(5, sizeof(unsigned char));
  }
  testshares[0][0] = 'h';
  testshares[0][1] = 'e';
  testshares[0][2] = 'y';
  testshares[0][3] = 'u';

  puts((const char *)testshares[0]);
  if (!shamirs_split(2,3,4,testshares,"/dev/random")) {
    testshares[0][0] = '\0';
    testshares[0][1] = '\0';
    testshares[0][2] = '\0';
    testshares[0][3] = '\0';
    free(testshares[2]);
    testshares[2] = NULL;
    if (!shamirs_combine(2,3,4,testshares)) {
      puts((const char *)testshares[0]);
    }
  }

  for (i = 0; i < 4; i++) {
    if(testshares[i] != NULL) {
      free(testshares[i]);
      testshares[i] = NULL;
    }
  }
  free(testshares);
  testshares = NULL;


  return 0;
}
#endif

#ifdef SHAMIRS_STANDALONE
int main(int argc, const char **argv)
{
#ifdef TEST_SHAMIRS
  return test_shamirs();
#else
  return shamirs_from_files(argc,argv);
#endif
}
#endif

