/* Added for Tor. */

#ifndef CRYPTO_INT64_H
#define CRYPTO_INT64_H

#include "torint.h"
#define crypto_int64 int64_t

/*
 Stop signed left shifts overflowing
 by using unsigned types for bitwise operations
*/

#ifndef OVERFLOW_SAFE_SIGNED_LSHIFT
#define OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, utype, stype) \
  ((stype)((utype)(s) << (utype)(lshift)))
#endif

#include "crypto_uint64.h"

#ifdef UNSAFE_SIGNED_LSHIFT
/* the original version of the code */
#define SHL64(s, lshift) s << lshift
#else /* #ifndef UNSAFE_SIGNED_LSHIFT */
#define SHL64(s, lshift) \
  OVERFLOW_SAFE_SIGNED_LSHIFT(s, lshift, crypto_uint64, crypto_int64)
#endif /* UNSAFE_SIGNED_LSHIFT */

#endif /* CRYPTO_INT64_H */
