// Copyright (c) 2018, The Tor Project, Inc.
// See LICENSE for licensing information

//! Floating point equality comparisons, with tolerances
//!
//! These functions compare f64 values for equality within absolute and
//! relative tolerances.

/// Compare two floating-point values, and return the greatest value. NaNs are
/// propagated.
///
/// # Inputs
///
/// * `a` and `b`: f64 input values. The function produces the same result for
///   `a, b` and `b, a`:
///
/// ```
/// let a = 0.10;
/// let b = 0.11;
/// assert!(crypto_rand_f64::max_f64(a, b) ==
///         crypto_rand_f64::max_f64(b, a));
/// ```
///
/// # Returns
///
/// The larger of `a` and `b`. If either `a` or `b` is NaN, returns a NaN.
///
/// # Examples
///
/// A number is its own maximum, including Infs and NaNs:
/// ```
/// use std::f64::*;
/// assert!(crypto_rand_f64::max_f64(1.0, 1.0) == 1.0);
/// assert!(crypto_rand_f64::max_f64(INFINITY, INFINITY) == INFINITY);
/// assert!(crypto_rand_f64::max_f64(NAN, NAN).is_nan());
/// ```
///
/// Standard arithmetic rules apply, even to infinities, but NaNs propagate:
/// ```
/// use std::f64::*;
/// assert!(crypto_rand_f64::max_f64(-3.0, 2.0) == 2.0);
/// assert!(crypto_rand_f64::max_f64(INFINITY, 5.0) == INFINITY);
/// assert!(crypto_rand_f64::max_f64(7.7, NAN).is_nan());
/// ```
///
/// # Panics
///
/// This function does not panic on any inputs.
///
/// # Notes
///
/// The precision of this function is the same as one of its inputs.
///
pub fn max_f64(a: f64, b: f64) -> f64 {
    // We can't use std::cmp::max(), because f64 is not Ord
    // Instead, we make sure NaNs propagate correctly
    if a.is_nan() {
        // prefer a's NaN bits
        a
    } else if b.is_nan() {
        b
    } else if a >= b {
        // if both are zero, prefer a's sign
        a
    } else {
        b
    }
}

/// Compare two floating-point values for equality, within certain tolerances.
///
/// # Inputs
///
/// * `a` and `b`: f64 values for comparison. The function produces the same
///   result for `a, b` and `b, a`:
///
/// ```
/// let a = 0.10;
/// let b = 0.11;
/// assert!(crypto_rand_f64::cmp_f64_tolerance(a, b, 0.0, 0.01) ==
///         crypto_rand_f64::cmp_f64_tolerance(b, a, 0.0, 0.01));
/// ```
///
/// * `relative_tolerance`, a non-negative f64 that is the permitted tolerance
///   relative to the sizes of `a` and `b`. The relative bound is calculated
///   based on whichever of `a` or `b` has larger magnitude.
///   A `relative_tolerance` of 0.0 only returns true if the values are
///   exactly equal, or the other tolerance is satisfied. An exception to this
///   rule is that a relative tolerance of 0.0 returns false when both values
///   are infinities.
///
/// * `absolute_tolerance`, a non-negative f64 that is the permitted tolerance
///   regardless of the sizes of `a` and `b`.
///   An `absolute_tolerance` of 0.0 only returns true if the values are
///   exactly equal, or the other tolerance is satisfied.
///
/// Similar rules apply to infinite tolerances, which almost always return
/// true.
///
/// # Returns
///
/// A bool that is true if either tolerance is satisfied, and false if the
/// difference between the values is outside both tolerances.
///
/// # Examples
///
/// Typically, floating point error is measured in "units in the last place"
/// (ulp). N ulp is a relative error of N.0*EPSILON.
/// ```
/// use std::f64::*;
/// // Encourage the compiler to store to RAM, which may result in
/// // double-rounding on some architectures.
/// // TODO: When does Rust store to RAM?
/// let three_sevenths = 3.0 / 7.0;
/// // These values can compare unequal if extended precision is used by the
/// // compiler, but they should still be within 2 units in the last place
/// assert!(crypto_rand_f64::cmp_f64_tolerance(three_sevenths, 3.0 / 7.0,
///                                            2.0 * EPSILON, 0.0));
/// ```
///
/// A number is always equal to itself, except for NaNs:
/// ```
/// use std::f64::*;
/// assert!(crypto_rand_f64::cmp_f64_tolerance(1.0, 1.0, 0.0, 0.0));
/// assert!(!crypto_rand_f64::cmp_f64_tolerance(NAN, NAN, 0.0, 0.0));
/// ```
///
/// Tolerances are independent:
/// ```
/// // The relative bound is: 2.0 * 0.6 = 1.2
/// assert!(crypto_rand_f64::cmp_f64_tolerance(1.0, 2.0, 0.6, 0.0));
/// assert!(crypto_rand_f64::cmp_f64_tolerance(1.0, 2.0, 0.0, 1.2));
/// ```
///
/// # Panics
///
/// This function will panic if:
/// * the inputs are outside their specified domains
///
/// This function panics rather than returning an error, because it is only
/// used in unit tests.
///
/// # Notes
///
/// For almost all inputs, this function will only produce an approximate
/// result. Since this function is designed to detect loss of precision,
/// we don't try to guard against loss of precision within the function.
///
/// Because it is only used in unit tests, the precision of this function is
/// not documented.
///
pub fn cmp_f64_tolerance(
    a: f64,
    b: f64,
    relative_tolerance: f64,
    absolute_tolerance: f64,
) -> bool {
    // check the domains of the inputs
    // a and b can be arbitrary values
    // relative_tolerance and absolute_tolerance must be non-negative
    assert!(relative_tolerance >= 0.0);
    assert!(absolute_tolerance >= 0.0);

    // the multiplication below involves a potential loss of precision
    // if relative_tolerance * max(a.abs(), b.abs()) is small.
    // Similarly, a - b suffers from catastrophic cancellation if a and b are
    // close.
    // We don't try to guard against these issues, see the Notes for an
    // explanation.

    // Handle infinities as a special case, and short-cut other equal values
    if a == b {
        true
    } else {
        // This is a standard numeric tolerance formula
        // TODO: reference
        let difference = (a - b).abs();
        let relative_bound = relative_tolerance * max_f64(a.abs(), b.abs());
        // We use max() rather than ||, so that a NaN propagates correctly
        difference <= max_f64(relative_bound, absolute_tolerance)
    }
}

// See also the function doctests
#[cfg(test)]
mod test {

    use super::*;
    use std::f64::*;

    /// Is `max_f64()` symmetric?
    /// Is `max_f64()` reflexive?
    #[test]
    fn test_max_f64_reflexive() {
        assert!(max_f64(2.0, 2.0) == 2.0);
        assert!(max_f64(-1.1, -1.1) == -1.1);
        // Infinities also work
        assert!(max_f64(-INFINITY, -INFINITY) == -INFINITY);
        // NaNs propagate
        assert!(max_f64(NAN, NAN).is_nan());
    }

    #[test]
    fn test_max_f64_symmetric() {
        assert!(max_f64(2.0, 2.0) == max_f64(2.0, 2.0));
        assert!(max_f64(1.0, 3.0) == max_f64(3.0, 1.0));
        assert!(max_f64(-1.1, -3.5) == max_f64(-3.5, -1.1));
        // Infinities also work
        assert!(max_f64(INFINITY, 0.55) == max_f64(0.55, INFINITY));
        assert!(max_f64(-INFINITY, 0.55) == max_f64(0.55, -INFINITY));
        assert!(max_f64(-INFINITY, INFINITY) == max_f64(INFINITY, -INFINITY));
        // NaNs propagate, regardless of position
        assert!(max_f64(NAN, 0.0).is_nan() == max_f64(0.0, NAN).is_nan());
        assert!(max_f64(NAN, NAN).is_nan() == max_f64(NAN, NAN).is_nan());
    }

    /// Does `max_f64()` work just like `std::cmp::max()` for ordered f64s?
    #[test]
    fn test_max_f64_is_maximum() {
        // Normal floats work as expected
        assert!(max_f64(2.0, 5.0) == 5.0);
        assert!(max_f64(-3.0, -1.5) == -1.5);
        // Signed zeroes are special
        assert!(max_f64(0.0, 0.0) == 0.0);
        assert!(max_f64(-0.0, -0.0) == -0.0);
        // But since 0.0 == -0.0, that doesn't matter
        assert!(max_f64(0.0, -0.0) == 0.0);
        assert!(max_f64(-0.0, 0.0) == 0.0);
        // Infinities also work
        assert!(max_f64(INFINITY, 1234.0) == INFINITY);
        assert!(max_f64(INFINITY, -1234.0) == INFINITY);
        assert!(max_f64(-INFINITY, 1.0) == 1.0);
        assert!(max_f64(-INFINITY, -1.0) == -1.0);
        assert!(max_f64(-INFINITY, INFINITY) == INFINITY);
        // NaNs propagate
        assert!(max_f64(0.0, NAN).is_nan());
        assert!(max_f64(NAN, INFINITY).is_nan());
        assert!(max_f64(NAN, -INFINITY).is_nan());
    }

    /// Does `cmp_f64_tolerance()` work just like == when the tolerances
    /// are zero?
    #[test]
    fn test_cmp_f64_tolerance_exact() {
        assert!(cmp_f64_tolerance(2.0, 2.0, 0.0, 0.0));
        assert!(!cmp_f64_tolerance(1.1, 1.2, 0.0, 0.0));
        assert!(cmp_f64_tolerance(-3.5, -3.5, 0.0, 0.0));
        assert!(cmp_f64_tolerance(0.0, 0.0, 0.0, 0.0));
        assert!(cmp_f64_tolerance(0.0, -0.0, 0.0, 0.0));
        assert!(cmp_f64_tolerance(-0.0, 0.0, 0.0, 0.0));
        // Infinities compare equal
        assert!(cmp_f64_tolerance(-INFINITY, -INFINITY, 0.0, 0.0));
        // NaNs never compare equal
        assert!(!cmp_f64_tolerance(NAN, NAN, 0.0, 0.0));
    }

    /// Does `cmp_f64_tolerance()` work when relative tolerances are used?
    #[test]
    fn test_cmp_f64_tolerance_relative() {
        assert!(cmp_f64_tolerance(0.01, 1.0, 1.0, 0.0));
        assert!(!cmp_f64_tolerance(2.0, 4.0, 0.1, 0.0));
        assert!(!cmp_f64_tolerance(-10.0, -6.0, 0.2, 0.0));
        // Infinities compare equal or less than, but only to other infinities
        assert!(cmp_f64_tolerance(1.0, INFINITY, 1.0, 0.0));
        assert!(cmp_f64_tolerance(1.0, INFINITY, INFINITY, 0.0));
        // 0.0 * Inf results in a NaN in the comparison
        assert!(!cmp_f64_tolerance(1.0, INFINITY, 0.0, 0.0));
        // NaNs never compare equal or less than
        assert!(!cmp_f64_tolerance(NAN, NAN, 2.0, 0.0));
    }

    /// Does `cmp_f64_tolerance()` work when absolute tolerances are used?
    #[test]
    fn test_cmp_f64_tolerance_absolute() {
        assert!(cmp_f64_tolerance(120.0, 100.0, 0.0, 90.0));
        assert!(!cmp_f64_tolerance(1.1, 1.0, 0.0, 0.01));
        assert!(cmp_f64_tolerance(-1.0, -2.0, 0.0, 1.1));
        // Infinities compare equal or less than, but only to other infinities
        assert!(!cmp_f64_tolerance(1.0, INFINITY, 0.0, 1.0));
        assert!(cmp_f64_tolerance(1.0, INFINITY, 1.0, INFINITY));
        // Inf * 0.0 results in a NaN in the comparison
        assert!(!cmp_f64_tolerance(1.0, INFINITY, 0.0, INFINITY));
        // Infs compare equal
        assert!(cmp_f64_tolerance(INFINITY, INFINITY, 0.0, INFINITY));
        // NaNs never compare equal or less than
        assert!(!cmp_f64_tolerance(NAN, NAN, 0.0, INFINITY));
    }

    /// Does `cmp_f64_tolerance()` work when both relative and absolute
    /// tolerances are used?
    #[test]
    fn test_cmp_f64_tolerances() {
        // Neither satisfied
        assert!(!cmp_f64_tolerance(1.0, 2.0, 0.1, 0.4));
        // Relative satisfied
        assert!(cmp_f64_tolerance(1.0, 2.0, 0.6, 0.4));
        // Absolute satisfied
        assert!(cmp_f64_tolerance(1.0, 2.0, 0.1, 1.1));
        // Both satisfied
        assert!(cmp_f64_tolerance(1.0, 2.0, 0.6, 1.1));

        // Relative Inf
        assert!(cmp_f64_tolerance(1.0, 100.0, INFINITY, 0.4));
        // Absolute Inf
        assert!(cmp_f64_tolerance(1.0, -300.0, 0.1, INFINITY));
        // Both Inf
        assert!(cmp_f64_tolerance(1.0, 2.0, INFINITY, INFINITY));

        // Relative NaN in the calculation
        assert!(!cmp_f64_tolerance(1.0, -INFINITY, 0.0, 0.4));
    }

    /// Does `cmp_f64_tolerance()` work on imprecise values?
    #[test]
    fn test_cmp_f64_imprecise() {
        // Encourage the compiler to store to RAM, which may result in
        // double-rounding on some architectures.
        // TODO: When does Rust store to RAM?
        let five_ninths = 5.0 / 9.0;
        // These values can compare unequal if extended precision is used by
        // the compiler, but they should still be within 2 units in the last
        // place
        assert!(cmp_f64_tolerance(
            five_ninths,
            5.0 / 9.0,
            2.0 * EPSILON,
            0.0
        ));
    }
}
