// Copyright (c) 2018, The Tor Project, Inc.
// See LICENSE for licensing information

//! Floating point limits
//!
//! These constants represent various floating point limits. They are derived
//! from the built-in floating point constants.

use std::f64::*;

/// The largest `f64` that has integer precision
/// The `f64` cast is safe, because this value has integer precision
pub const F64_INTEGER_MAX_AS_U64: u64 = 1 << MANTISSA_DIGITS;
pub const F64_INTEGER_MAX: f64 = F64_INTEGER_MAX_AS_U64 as f64;

/// Integers equal to `F64_INTEGER_MAX` are exactly representable in `f64`
#[test]
fn test_f64_integer_max_exact() {
    // These tests are deliberate floating point precision tests
    assert!(F64_INTEGER_MAX as u64 == F64_INTEGER_MAX_AS_U64);
    assert!(F64_INTEGER_MAX == F64_INTEGER_MAX_AS_U64 as f64);
}

/// Integers less than `F64_INTEGER_MAX` are exactly representable in `f64`
#[test]
fn test_f64_integer_max_decrement_exact() {
    // These tests are deliberate floating point precision tests
    assert!(F64_INTEGER_MAX - 1.0 != F64_INTEGER_MAX);
    assert!((F64_INTEGER_MAX - 1.0) as u64 == F64_INTEGER_MAX_AS_U64 - 1);
    assert!((F64_INTEGER_MAX as u64) - 1 == F64_INTEGER_MAX_AS_U64 - 1);
    assert!(F64_INTEGER_MAX - 1.0 == (F64_INTEGER_MAX_AS_U64 - 1) as f64);
    assert!(F64_INTEGER_MAX - 1.0 == (F64_INTEGER_MAX_AS_U64 as f64) - 1.0);
}

/// Some integers greater than `F64_INTEGER_MAX` are not exactly representable
/// in `f64`.
#[test]
fn test_f64_integer_max_increment_inexact() {
    // These tests are deliberate floating point precision tests
    // These tests may fail if rustc uses extended precision floats
    assert!(F64_INTEGER_MAX + 1.0 == F64_INTEGER_MAX);
    assert!((F64_INTEGER_MAX + 1.0) as u64 == F64_INTEGER_MAX_AS_U64);
    assert!((F64_INTEGER_MAX as u64) + 1 == F64_INTEGER_MAX_AS_U64 + 1);
    assert!(F64_INTEGER_MAX + 1.0 == F64_INTEGER_MAX_AS_U64 as f64);
}
