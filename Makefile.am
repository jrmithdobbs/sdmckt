ACLOCAL_AMFLAGS = -I m4
# Make sure everything gets packaged!
EXTRA_DIST = autogen.sh autoclean.sh include src doc

AM_CPPFLAGS = -Wall -pedantic -I$(top_srcdir)/include

bin_PROGRAMS = sdmckt
noinst_PROGRAMS = test-sdmckt

scryptenc_sources = \
	src/scrypt/util/memlimit.c  src/scrypt/util/readpass.c \
	src/scrypt/util/warn.c  src/scrypt/scryptenc/scryptenc.c \
	src/scrypt/scryptenc/scryptenc_cpuperf.c  \
	src/scrypt/crypto/crypto_aesctr.c \
	src/scrypt/crypto/sha256.c  \
	src/scrypt/crypto/crypto_scrypt-sse.c \
	src/scrypt/crypto/crypto_scrypt-nosse.c \
	src/scrypt/crypto/crypto_scrypt-ref.c

shared_sources = src/auth.c src/oracle_yubikey.c src/secret.c \
	src/shamirs.c src/util.c src/ykchalresp.c $(scryptenc_sources)

sdmckt_SOURCES = src/sdmckt.c $(shared_sources)
test_sdmckt_SOURCES = src/test-sdmckt.c $(shared_sources)

.PHONY: test

test: test-sdmckt
	./test-sdmckt
