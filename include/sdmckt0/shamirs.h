#ifndef __SDMCKT_shamirs_h
#define __SDMCKT_shamirs_h
/*
 Apply Shamir's Secret Sharing algorithm for splitting secrets.
 M = Number of shares necessary to recombine.
 N = Number of shares to create.
 datalen = size of each share/data
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
*/
extern int shamirs_split(unsigned char M, unsigned char N,
    size_t datalen, unsigned char ** shares,
    const char * random_dev_path);

/*
 Apply Shamir's Secret Sharing algorithm for recombination.
 M = Number of shares necessary to recombine.
 N = Number of shares originally created.
 datalen = size of each share/data
 shares = array of buffers for created shares. The 0 indexed item should be the source.
  The index of the shares array is significant. If a share is returned as index 1 it should
  be passed back in as index 1. If recombining secrets split where M<N any missing secrets
  should be set to NULL and will be skipped.
 All memory management is left to the caller.
 Return values:
  0 == Success.
  1 == Invalid M/N values.
  3 == Not enough shares for recombination.
*/
extern int shamirs_combine(unsigned char M, unsigned char N,
    size_t datalen, unsigned char ** shares );
#endif
