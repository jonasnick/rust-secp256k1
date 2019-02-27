// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # FFI bindings
//! Direct bindings to the underlying C library functions. These should
//! not be needed for most users.
use std::mem;
use std::hash;
use std::os::raw::{c_int, c_uchar, c_uint, c_void};
use secp256k1::ffi::{Context, NonceFn, PublicKey};

#[repr(C)] pub struct ScratchSpace(c_int);

/// Library-internal representation of a Secp256k1 Schnorr signature
#[repr(C)]
pub struct SchnorrSignature([c_uchar; 64]);
impl_array_newtype!(SchnorrSignature, c_uchar, 64);
impl_raw_debug!(SchnorrSignature);

impl SchnorrSignature {
    /// Create a new (zeroed) signature usable for the FFI interface
    pub fn new() -> SchnorrSignature { SchnorrSignature([0; 64]) }
    /// Create a new (uninitialized) signature usable for the FFI interface
    pub unsafe fn blank() -> SchnorrSignature { mem::uninitialized() }
}

extern "C" {
    pub fn secp256k1_scratch_space_create(
        cx: *const Context,
        max_size: usize,
    ) -> *mut ScratchSpace;

    pub fn secp256k1_scratch_space_destroy(
        scratch: *mut ScratchSpace,
    );

    pub fn secp256k1_schnorrsig_parse(
        cx: *const Context,
        sig: *mut SchnorrSignature,
        in64: *const c_uchar,
    ) -> c_int;

    pub fn secp256k1_schnorrsig_serialize(
        cx: *const Context,
        out64: *mut c_uchar,
        sig: *const SchnorrSignature,
    ) -> c_int;

    pub fn secp256k1_schnorrsig_sign(
        cx: *const Context,
        sig: *mut SchnorrSignature,
        nonce_is_negated: *mut c_int,
        msg32: *const c_uchar,
        sk: *const c_uchar,
        noncefn: NonceFn,
        noncedata: *mut c_void,
    ) -> c_int;

    pub fn secp256k1_schnorrsig_verify(
        cx: *const Context,
        sig: *const SchnorrSignature,
        msg32: *const c_uchar,
        pk: *const PublicKey,
    ) -> c_int;


    pub fn secp256k1_schnorrsig_verify_batch(
        cx: *const Context,
        scratch: *mut ScratchSpace,
        sig: *const *const SchnorrSignature,
        msg32: *const *const c_uchar,
        pk: *const *const PublicKey,
        n_sigs: usize,
    ) -> c_int;
}
