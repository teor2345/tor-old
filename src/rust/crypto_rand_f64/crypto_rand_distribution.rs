// Copyright (c) 2018, The Tor Project, IAnc. */AA
// See LICENSE for licensing information */

//! Random distribution calculations
//!
//! These functions calculate the expected values of random trials.
//! They are used by the crypto_rand_f64 tests.

use std::f64::*;

/// Get the approximate standard deviation for a finite binomial
/// distribution.
///
/// # Inputs
///
/// * `probability`, an f64 in [0.0, 1.0] that is the probability of one
///    of the values in the binomial distribution. The function produces
///    approximately the same result for `probability` and
///    `1.0 - probability`.
///
/// * `range`, a finite, non-negative f64 that is the difference between
///   the two values in the distribution. For a standard (0.0, 1.0)
///   binomial distribution, `range` is `1.0 - 0.0 = 1.0`.
///
/// * `trials`, a non-zero u64 that is the number of trials used to
///   produce the binomial distribution.
///
/// # Returns
///
/// An f64 that is an approximation of the standard devation for the
/// specified binomial distribution. Standard deviations for finite
/// distributions are finite and non-negative. The largest standard
/// deviation for a set `trials` and `range` occurs when
/// `probability = 0.5`.
///
/// The variance of an Binomial(n,p) distribution is np(1−p)
/// https://en.wikipedia.org/wiki/Binomial_distribution
/// and the standard deviation is the square root of the variance. 
///
/// # Examples
///
/// A single coin toss has a standard deviation of 0.5:
/// ```
/// let stddev_1 = get_binomial_standard_deviation(0.5, 1.0, 1);
/// // All the inputs, intermediate results, and ouputs are exactly
/// // representable as f64, and all the operations used are exactly
/// // specified by IEEE 754, so it is safe to use == on these floats
/// assert!(stddev_1 == 0.5);
/// ```
///
/// The bits in a random mebibit have a standard deviation of 512:
/// ```
/// let stddev_1m = get_binomial_standard_deviation(0.5, 1.0, 1024*1024);
/// // It is safe to use == on this floating point value, because it
/// // satisfies the same conditions as the single coin toss example.
/// assert!(stddev_1m == 512.0);
/// ```
///
/// An 0.1-biased distribution of (-10.0, 10.0) with 100 trials has this
/// standard deviation:
/// ```
/// let stddev_bias = get_binomial_standard_deviation(0.1, 20.0,
///                                                   100);
/// // check the upper bound
/// assert!(stddev_bias < 0.5*(20.0 * 100.0).sqrt());
/// // TODO: approximate comparison
/// assert!(stddev_bias >= 13.416);
/// assert!(stddev_bias <= 13.417);
/// ```
///
/// # Panics
///
/// This function will panic if:
/// * the inputs are outside their specified domains
/// * the probability is too small for an accurate calculation
/// * the result is outside the expected range of values
///
/// This function panics rather than returning an error, because it is only
/// used in unit tests.
///
/// # Notes
///
/// For almost all inputs, this function will only produce an approximate
/// result. Because it is only used in unit tests, the precision of this
/// result is not documented.
///
pub fn get_binomial_standard_deviation(probability: f64,
                                       range: f64,
                                       trials: u64) -> f64 {
    // check the domains of the inputs
    // probability is in [0.0, 1.0]
    assert!(probability >= 0.0);
    assert!(probability <= 1.0);
    // range is non-negative and finite
    assert!(range >= 0.0);
    assert!(range.is_finite());
    // trials is non-zero
    assert!(trials > 0);
    
    // check for potential loss of precision
    // this subtraction suffers from catastrophic cancellation if the
    // optimiser uses n * (p - p^2), but only if p^2 is small
    assert!(probability * probability > EPSILON);

    // small floating point errors in these calculations are irrelevant,
    // because we only need an approximate upper bound
    let variance = (trials as f64) * probability * (1.0 - probability) * range;
    let stddev = variance.sqrt();
    
    // check that the result is in the expected range
    // stddev is non-negative, and has an upper bound when p = 0.5
    assert!(stddev >= 0.0);
    // TODO: approximate comparison
    assert!(stddev <= 0.5*(range * (trials as f64)).sqrt()*(1.0 + EPSILON));
    
    stddev
}

// TODO: unit tests
