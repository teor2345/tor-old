//! Copyright (c) 2016-2017, The Tor Project, Inc.
//! See LICENSE for licensing information

//! Cryptographically secure random floating point number generation
//!
//! A drop-in replacement for some of Tor's cryptographically random number
//! generation functions. Also contains some extra tests.

// These modules are only used by external crate tests, but they also contain
// doc tests, which seem to need access to the functions at a module level.
//
// And if I make these module private, I get dead code warnings.
//
// TODO: is there a better way?
pub mod tolerance_f64;
pub use tolerance_f64::*;

pub mod limits_f64;
pub use limits_f64::*;
