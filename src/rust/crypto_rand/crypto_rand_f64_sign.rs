// Copyright (c) 2018, The Tor Project, Inc. */
// See LICENSE for licensing information */

use std::bool;
use std::f64;

// TODO: use crypto_rand from Tor instead
use rand::random;

// TODO: describe typical floating point issues:
// discretization / limited precision
// catastrophic cancellation
// double rounding

/// Get a random floating-point positive or negative sign.
///
/// # Returns
///
/// A f64 that is either `+1.0` or `-1.0`, with equal probability.
///
/// # Examples
///
/// The function returns two possible values: 
/// ```
/// let signed_f64 =  get_random_f64_sign();
/// // 1.0 is exactly representable as f64, so it is safe to use == here
/// assert!(signed_f64 == +1.0 or signed_f64 == -1.0);
/// ```
///
/// Typical usage:
/// ```
/// let signed_kilo = get_random_f64_sign() * 1024.0;
/// // 1024.0 is exactly representable as f64, so it is safe to use == here
/// assert!(signed_kilo == +1024.0 or signed_kilo == -1024.0);
/// ```
///
//  C_RUST_COUPLED: src/or/crypto_rand_double.c `crypto_rand_double_sign`
pub(crate) fn get_random_f64_sign() -> f64 {
    if random() {
        +1.0
    } else {
        -1.0
    }
}

#[cfg(test)]
mod test {
    
    #[test]
    fn test_random_f64_sign_classify() {
        // true if the number is neither zero, infinite, subnormal, or NaN
        assert!(get_random_f64_sign().is_normal());
    }

    #[test]
    fn test_random_f64_sign_magnitude() {
        // 1.0 is exactly representable as f64, so it is safe to use eq here
        assert_eq!(get_random_f64_sign().abs(), 1.0);
    }

    #[test]
    fn test_random_f64_sign_alternatives() {
        let rand_sign = get_random_f64_sign();
        // 1.0 is exactly representable as f64, so it is safe to use == here
        assert!(rand_sign == +1.0 or rand_sign == -1.0);
    }

    // Use the same number of iterations as test_crypto.c
    const RANDOM_TEST_ITERATIONS = 1000

    #[test]
    fn test_random_f64_sign_both_values_occur() {
        // Copied from test_crypto_rng_range()
        let got_positive = false;
        let got_negative = false;
        for _ in 0..RANDOM_TEST_ITERATIONS {
            if get_random_f64_sign() > 0.0 {
                got_positive = true;
            } else {
                got_negative = true;
            }
        }
        // These fail with probability 1/2^1000
        assert!(got_positive);
        assert!(got_negative);
    }

    fn binomial_standard_deviation(probability: f64, trials: u64) -> f64 {
        // if Y follows a Binomial(n,p) distribution, then VarY = np(1−p)
        // https://math.stackexchange.com/questions/1636867/mean-and-standard-deviation-after-a-coin-is-tossed#1636895
        //
        // this subtraction suffers from catastrophic cancellation if the
        // optimiser uses n * (p - p^2), but only if p^2 is small
        //
        // small floating point errors are irrelevant, because we only need
        // an approximate upper bound
        assert(probability * probability > DOUBLE_EPSILON);
        let variance = trials * probability * (1.0 - probability)
        variance.sqrt()
    }

    #[test]
    fn test_random_f64_sign_even_distribution() {
        let accumulator = 0.0;
        for _ in 0..RANDOM_TEST_ITERATIONS {
            // This addition is exact, and does not suffer from catastropic
            // cancellation, as long as RANDOM_TEST_ITERATIONS is low enough
            assert!(RANDOM_TEST_ITERATIONS < 2^52)
            accumulator += get_random_f64_sign();
        }
        let stdev = binomial_standard_deviation(0.5, RANDOM_TEST_ITERATIONS);
        // This fails with probability 1/10^23 if the values are evenly
        // distributed, which is similar to the RAM bit error probability
        // https://en.wikipedia.org/wiki/Standard_deviation#Rules_for_normally_distributed_data
        // http://www.aleph.se/andart/archives/2009/09/ten_sigma_numerics_and_finance.html
        //
        // small floating point errors are irrelevant, because we only need
        // an approximate upper bound
        let ten_sigma = 10.0 * stdev;
        assert!(accumulator.abs() < ten_sigma);
    }
}
