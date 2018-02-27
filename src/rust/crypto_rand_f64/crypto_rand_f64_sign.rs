// Copyright (c) 2018, The Tor Project, Inc. */
// See LICENSE for licensing information */

//! Generates signed f64 values at random
//!
//! This module implements `get_rand_f64_sign()`, which returns a random f64
//! sign, either 1.0, or -1.0. It's not very useful by itself, and should be
//! used with other functions that produce random f64 values.
//!
//! If you need a randomly distributed positive or negative value, multiply by
//! `get_rand_f64_sign()`, rather than using other tricks that lose
//! precision.

extern crate rand;

//use std::bool;
use std::f64;

// TODO: use crypto_rand from Tor, once it's wrapped in Rng
use self::rand::random;

// TODO: describe typical floating point issues:
// discretization / limited precision
// catastrophic cancellation
// double rounding
// transcendental functions vs exactly specified operations

/// Get a random floating-point positive or negative value of magnitude 1.0.
///
/// # Returns
///
/// An f64 that is either `1.0` or `-1.0`, with equal probability.
///
/// # Examples
///
/// The function returns one of two possible values:
/// ```
/// let signed_f64 = crypto_rand_f64::get_rand_f64_sign();
/// // 1.0 is exactly representable as f64, so it is safe to use == on these
/// // floating point values
/// assert!(signed_f64 == 1.0 || signed_f64 == -1.0);
/// ```
///
/// Typical usage:
/// ```
/// let signed_kilo = crypto_rand_f64::get_rand_f64_sign() * 1024.0;
/// // 1024.0 is exactly representable as f64, and abs() is exactly defined by
/// // IEEE 754, so it is safe to use == on these floating point values
/// assert!(signed_kilo.abs() == 1024.0);
/// ```
///
/// With an imprecise value:
/// ```
/// let signed_frac = crypto_rand_f64::get_rand_f64_sign() * 3.0/7.0;
/// // TODO: approximate comparison
/// // This test can fail if extended precision is used by the compiler.
/// assert!(signed_frac.abs() == 3.0/7.0);
/// ```
///
/// # Panics
///
/// This function will panic if:
/// * the underlying Rng panics.
///
//  C_RUST_COUPLED: src/or/crypto_rand_double.c `crypto_rand_double_sign`
pub fn get_rand_f64_sign() -> f64 {
    if random() {
        1.0
    } else {
        -1.0
    }
}

#[cfg(test)]
mod test {

    use super::*;

    /// Does `get_rand_f64_sign()` return a normal f64 value?
    #[test]
    fn test_rand_f64_sign_classify() {
        // true if the number is neither zero, infinite, subnormal, or NaN
        assert!(get_rand_f64_sign().is_normal());
    }

    /// Does `get_rand_f64_sign()` return a f64 value with the correct
    /// magnitude?
    #[test]
    fn test_rand_f64_sign_magnitude() {
        // 1.0 is exactly representable as f64, so it is safe to use assert_eq
        // on this floating point value
        assert_eq!(get_rand_f64_sign().abs(), 1.0);
    }

    /// Does `get_rand_f64_sign()` return one of the two alternative f64
    /// values?
    #[test]
    fn test_rand_f64_sign_alternatives() {
        let rand_sign = get_rand_f64_sign();
        // 1.0 is exactly representable as f64, so it is safe to use == on this
        // floating point value
        assert!(rand_sign == 1.0 || rand_sign == -1.0);
    }
}
