// Copyright (c) 2018, The Tor Project, Inc. */
// See LICENSE for licensing information */

//! FFI functions, only to be called from C.
//!
//! Equivalent C versions of this api are in `src/or/crypto_rand.c` (TODO)
//!
//! For an explanation of how c_double can be passed across the FFI boundary,
//! see https://doc.rust-lang.org/std/primitive.f64.html#method.from_bits

use libc::{c_double};

use crypto_rand_f64_sign::*;

/// Provide an interface for C to translate arguments and return types for
/// crypto_rand_f64::get_rand_f64_sign
#[no_mangle]
pub extern "C" fn crypto_rand_double_sign() -> c_double {
    get_rand_f64_sign()
}
