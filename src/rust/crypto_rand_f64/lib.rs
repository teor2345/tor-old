//! Copyright (c) 2016-2017, The Tor Project, Inc. */
//! See LICENSE for licensing information */

//! Cryptographically secure random number generation
//!
//! A drop-in replacement for some of Tor's cryptographically random number
//! generation functions.
//!
//! TODO: expand?

extern crate libc;

mod crypto_rand_f64_sign;

pub mod ffi;

pub use crypto_rand_f64_sign::get_rand_f64_sign;

// These modules are only used by external crate tests, but they also contain
// doc tests themselves
//
// TODO: is there a better way?
mod crypto_rand_distribution;

pub use crypto_rand_distribution::get_binomial_standard_deviation;
