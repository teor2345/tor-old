// Copyright (c) 2018, The Tor Project, Inc.
// See LICENSE for licensing information

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

// TODO: ThreadRng's default ISAAC implementation may not meet modern CSPRNG
//       standards: https://github.com/dhardy/rand/issues/53
// TODO: use crypto_rand from Tor, once it's wrapped in Rng
use self::rand::*;

// TODO: describe typical floating point issues:
// discretization / limited precision
// catastrophic cancellation
// double rounding
// exactly specified operations
// transcendental functions
// - table-makers dilemma
// - cyclic functions and modulus(?) errors

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
/// use std::f64::*;
/// let signed_frac = crypto_rand_f64::get_rand_f64_sign() * 1.0 / 3.0;
/// // This test can compare unequal if extended precision is used by the
/// // compiler, but they should still be within 2 units in the last place
/// assert!(crypto_rand_f64::cmp_f64_tolerance(signed_frac.abs(), 1.0 / 3.0,
///                                            2.0 * EPSILON, 0.0));
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
