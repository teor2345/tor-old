/* Added for Tor. */

#ifndef CRYPTO_INT32_H
#define CRYPTO_INT32_H

#include "torint.h"
#define crypto_int32 int32_t
#define crypto_uint32 uint32_t

/*
 Stop signed left shifts overflowing
 by using unsigned types for 8-bit & 32-bit bitwise operations
 */

#define SHL8(s, lshift) \
  OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, unsigned char, signed char)
#define SHL32(s, lshift) \
  OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, crypto_uint32, crypto_int32)

#endif /* CRYPTO_INT32_H */
