/*
 Original comments from David Madore <david.madore@ens.fr>
 with minor formatting changes follow after this comment block.

 His original implementation can be found at:
  ftp://quatramaran.ens.fr/pub/madore/misc/shsecret.c

 My changes statically define the lookup tables, segregate the
 global variables into the shamirs_state struct, moved the filename
 and fd storage arrays into shamirs_from_files() function,
 and renamed some functions. Additionally I have added the shamirs()
 function which performs the described operations on buffers instead
 of files. Along with shamirs_split() and shamirs_combine()
 convenience functions that hide the implementation details from the
 user.

 To compile this code in a way that operates as Mr Madore describes
 below you can use the following gcc command:
   gcc -g -std=c89 -pedantic -Wall -O3 -DSHAMIRS_STANDALONE \
   -o shamirs shamirs.c
 
 To compile this code in a way that tests the shamirs() buffer-based
 function you can use the following gcc command:
   gcc -g -std=c89 -pedantic -Wall -O3 -DSHAMIRS_STANDALONE \
   -DTEST_SHAMIRS  -o shamirs shamirs.c

 Additionally, in the spirit of his generous donation all changes
 contained in this file, shamirs.c, shamirs.h, and shamirs_constants.h
 are hereby left in the Public Domain.

 Modified by Douglas Huff <dhuff@jrbobdobbs.org>
 2011/08/02 - Public Domain

 While this software is in the public domain I share Mr Madore's plea
 at this bottom of this file.
*/

/*
 shsecret.c - Secret sharing algorithm
 Written by David Madore <david.madore@ens.fr>
 2000/06/19 - Public Domain
*/

/*
 This program implements a secret sharing algorithm.  In other
 words, given a file (secret), it can produce N files of the same
 size ("shares") such that knowing any M shares among N will be
 sufficient to recover the secret (using this very program again)
 whereas knowing less than M shares will yield _absolutely no
 information_ on the secret, even with infinite computing power.
 This program does both the sharing and the unsharing (it actually
 does a little more than that).  N can be anywhere up to 255.  M can
 be anywhere up to N.
*/

/*
 Features:
  + Small is beautiful.
  + Efficient (for small MN).
  + No bignum arithmetic (only eight-bit calculations).
  + Completely portable (only assumes input chars are eight-bit).
  + No dynamic memory allocation whatsoever (roughly 70k static).
  + Completely brain-dead command line syntax.
*/

/*
 How to use:
 + To share a secret:
   shsecret -secret.txt 1-/dev/urandom 2-/dev/urandom [...] \
    1+share1.dat 2+share2.dat 3+share3.dat [...]
   where the number of '-' command line arguments is M-1 and where the
   number of '+' command line arguments is N.
   If your system has no /dev/urandom-like random number generator,
   then write (cryptographically strong) random data in share1.dat,
   share2.dat and so on (M-1 of them), each one being the same size
   as secret.txt (at least) and run:
   shsecret -secret.txt 1-share1.dat 2-share2.dat [...] \
    M+shareM.dat [...]
   (that is, use a '-' for the first M-1 and a '+' for the following
   ones).  Then share1.dat through shareN.dat are the N shares.
 + To unshare a secret:
   shsecret 1-share1.dat 3-share3.dat 4-share4.dat [...] +secret.txt
   Enough shares must be given (i.e. at least M), but which are given
   is unimportant.
*/

/*
 Detailed instructions:
 Syntax is "shsecret [point][+-][file] [...]"
 Where [point] is an integer between 0 and 255 (if missing, counted
 as 0; [+-] is either '+' for an output file or '-' for an input
 file; and [file] is a file name.
 This computes the so-called "Lagrange interpolating polynomial" on
 the input files through the given input points and outputs its
 values at the given output points in the given output files.  The
 Lagrange interpolating polynomial, if defined by M input points, is
 completely determined by its value at _any_ M points.
 In particular, if shsecret is run with secret.txt as input file for
 point 0 and M-1 sets of random data for points 1 to M-1, it will
 create a Lagrange interpolating polynomial of degree M which is
 random except that its value at 0 is given by secret.txt; its value
 at any point other than 0 is random.  Given M such values, the
 polynomial can be recovered, hence, in particular, its value at 0
 (the secret).
*/

/*
 Concise mathematical details (you may skip this but read below):
 We work in the Galois field F256 with 256 elements represented by
 the integers from 0 to 255.  The two operations ("addition" and
 "multiplication") of the field are the exclusive or and the Conway
 multiplication.  Exclusive or can be defined (by induction) as
   a xor b = the smallest n not equal to a' xor b for a'<a
       nor to a xor b' for b'<b
 Similarly, Conway multiplication can be defined as
   a conmul b = the smallest n not equal to
        (a' conmul b) xor (a' conmul b') xor (a conmul b')
        for some a'<a and b'<b
 Note that 0 and 1 in the field are the true 0 and 1.
 Note that the field has characteristic 2, so substraction is
 precisely the same thing as addition (namely, exclusive or);
 nevertheless I will write + and - as needed in what follows for
 greater clarity.
 Suppose zi are the output points and xj the input points (for
 various values of i and j); suppose yj is the input data for input
 point xj (i.e. one byte of the corresponding input file).  We wish
 to compute the output data ti corresponding to zi.  The polynomial
 (Conway) product of the (X-xk) for k not equal to j is equal to 0
 at every xk except xj where it is not zero; we call in_cross[j] its
 value at xj.  If we (Conway) divide the product of the (X-xk) by
 in_cross[j] we get a polynomial which is 1 at xj and 0 at every
 other xk: call it Pj.  The sum (i.e. XOR) of the yj Pj is the
 Lagrange interpolating polynomial: it takes value yj at each xj.
 So its value at zi is the sum of the yj Pj(zi).  Now Pj(zi) is the
 product of the (zi-xk) for k not equal to j, divdided by
 in_cross[j].  Call out_cross[i] the product of the (zi-xk) for
 _every_ k.  Then Pj(zi) is out_cross[i] divided by the product of
 (zi-xj) by in_cross[j].  This is expression is the horrible
 conmul_tab[out_cross[i]][coninv_tab[conmul_tab[in_cross[j]]
   [out_points[i]^in_points[j]]]]
 further down in this program (here out_points[i] is zi,
 in_points[j] is xj and ^ is the XOR operation; and conmul_tab is
 the table giving the Conway multiplication and coninv_tab is the
 table giving the Conway inverse operation).
*/

/*
 Note: your secret sharing system will only be secure provided you
 feed the program with _cryptographically secure random numbers_.
*/

/*
 Note: all input and output files are open simultaneously.  Your
 system must have enough file descriptors.
*/

/*
 Speed estimation: circa 350kB/s on an Intel PIII-600 running Linux
 with NM=30.  Speed decreases linearly in proportion with NM.  Thus
 we have a theoretical speed of circa 10MB/s.
*/

/*
 Plea: although I put this file in the Public Domain, I would very
 much appreciate getting credit if credit is due.  Thank you.
*/

