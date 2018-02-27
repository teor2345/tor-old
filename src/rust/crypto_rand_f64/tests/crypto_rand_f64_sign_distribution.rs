// Copyright (c) 2018, The Tor Project, IAnc. */AA
// See LICENSE for licensing information */

//! Random distribution tests
//!
//! These tests check if the crypto_rand functions produce the expected
//! random distributions. They check the outcome of a limited number of
//! samples, so they have a small probability of failing by chance.
//!
//! These tests may be slower than other tests, because they loop many times.

extern crate crypto_rand_f64;

use std::f64::*;

use crypto_rand_f64::*;

/// Use the same number of iterations as test_crypto.c
const RANDOM_TEST_ITERATIONS : u64 = 1000;

/// The largest f64 that has integer precision
const F64_INTEGER_MAX : f64 = ((1 as u64) << MANTISSA_DIGITS) as f64;

/// Integers less than F64_INTEGER_MAX are exactly representable in f64
#[test]
fn test_f64_integer_max_decrement_exact() {
    // This is a deliberate floating point precision test
    assert!(F64_INTEGER_MAX - 1.0 != F64_INTEGER_MAX);
}

/// Some integers greater than F64_INTEGER_MAX are not exactly representable
/// in f64.
#[test]
fn test_f64_integer_max_increment_inexact() {
    // This is a deliberate floating point precision test
    // This test may fail if rustc uses extended precision floats.
    assert!(F64_INTEGER_MAX + 1.0 == F64_INTEGER_MAX);
}

/// Do both outputs of `get_rand_f64_sign()` occur at all?
#[test]
fn test_rand_f64_sign_both_values_occur() {
    // Similar to C's test_crypto_rng_range()
    let mut got_positive = false;
    let mut got_negative = false;
    for _ in 0..RANDOM_TEST_ITERATIONS {
        if get_rand_f64_sign() > 0.0 {
            got_positive = true;
        } else {
            got_negative = true;
        }
    }
    // These fail with probability 1/2^1000
    assert!(got_positive);
    assert!(got_negative);
}

/// Do both outputs of `get_rand_f64_sign()` occur with the expected
/// distribution?
#[test]
fn test_rand_f64_sign_even_distribution() {
    let mut accumulator = 0.0;
    for _ in 0..RANDOM_TEST_ITERATIONS {
        // Check RANDOM_TEST_ITERATIONS is not too large
        // The u64 cast is safe, because F64_INTEGER_MAX has integer precision
        assert!(RANDOM_TEST_ITERATIONS <= (F64_INTEGER_MAX as u64));
        // This floating-point addition is exact, and does not suffer from
        // catastropic cancellation, as long as RANDOM_TEST_ITERATIONS is not
        // too large
        accumulator += get_rand_f64_sign();
    }
    let stdev = get_binomial_standard_deviation(0.5,
                                                2.0,
                                                RANDOM_TEST_ITERATIONS);
    
    // A ten-sigma test fails with probability 1/10^23, which is similar
    // to the RAM bit error probability 5 * 10^-7. We use a lower value
    // than the crypto_rand unit tests, because we want to catch skewed
    // distributions.
    //
    // Sources:
    // https://en.wikipedia.org/wiki/Standard_deviation#Rules_for_normally_distributed_data
    // http://www.aleph.se/andart/archives/2009/09/ten_sigma_numerics_and_finance.html
    // http://www.zdnet.com/article/dram-error-rates-nightmare-on-dimm-street/
    let ten_sigma = 10.0 * stdev;
    
    // check that the f64 cast below is safe
    assert!(RANDOM_TEST_ITERATIONS <= (F64_INTEGER_MAX as u64));
    // check that we haven't set ten_sigma too high
    // (otherwise, this test will never fail)
    assert!(ten_sigma < (RANDOM_TEST_ITERATIONS as f64));
    // check if the probability distribution is skewed
    assert!(accumulator.abs() < ten_sigma);
}
