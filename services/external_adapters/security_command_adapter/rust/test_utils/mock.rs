/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Simple mock framework to replace mockall for OpenHarmony platform
//!
//! Usage:
//! ```rust
//! let mut mock = MockTimeKeeper::new();
//! mock.expect_get_rtc_time().returning(|| Ok(1000));
//! mock.expect_get_rtc_time().returning(|| Ok(2000)); // sequence support
//! ```

use crate::common::constants::*;
use crate::common::types::*;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, KeyPair, RandomChecker};
use crate::traits::event_manager::Event;
use crate::Vec;
use core::cell::{Cell, RefCell};

/// Expectation for methods with 0 arguments
pub struct Expectation0<R> {
    expectations: RefCell<Vec<Box<dyn FnMut() -> R>>>,
}

impl<R> Expectation0<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut() -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call(&self) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])()
        } else {
            let mut f = expectations.remove(0);
            f()
        }
    }
}

impl<R> Default for Expectation0<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 1 argument
/// Uses &'static lifetime for simplicity in test code
pub struct Expectation1<R, A: Copy + 'static> {
    expectations: RefCell<Vec<Box<dyn FnMut(A) -> R>>>,
}

impl<R, A: Copy + 'static> Expectation1<R, A> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(A) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call(&self, arg: A) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(arg)
        } else {
            let mut f = expectations.remove(0);
            f(arg)
        }
    }
}

impl<R, A: Copy + 'static> Default for Expectation1<R, A> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 2 arguments
pub struct Expectation2<R, A: Copy + 'static, B: Copy + 'static> {
    expectations: RefCell<Vec<Box<dyn FnMut(A, B) -> R>>>,
}

impl<R, A: Copy + 'static, B: Copy + 'static> Expectation2<R, A, B> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(A, B) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call(&self, arg1: A, arg2: B) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(arg1, arg2)
        } else {
            let mut f = expectations.remove(0);
            f(arg1, arg2)
        }
    }
}

impl<R, A: Copy + 'static, B: Copy + 'static> Default for Expectation2<R, A, B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with slice arguments (like &[u8])
/// Stores the slice data to handle lifetime issues
pub struct ExpectationSlice1<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&[u8]) -> R>>>,
}

impl<R> ExpectationSlice1<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&[u8]) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a [u8]) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            // Extend lifetime to 'static - safe for test closures that don't store the reference
            (expectations[0])(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg) })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg) })
        }
    }
}

impl<R> Default for ExpectationSlice1<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 2 slice arguments
pub struct ExpectationSlice2<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&[u8], &[u8]) -> R>>>,
}

impl<R> ExpectationSlice2<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&[u8], &[u8]) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a, 'b>(&self, arg1: &'a [u8], arg2: &'b [u8]) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg1) }, unsafe {
                std::mem::transmute::<&'b [u8], &'static [u8]>(arg2)
            })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg1) }, unsafe {
                std::mem::transmute::<&'b [u8], &'static [u8]>(arg2)
            })
        }
    }
}

impl<R> Default for ExpectationSlice2<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 1 string argument (&str)
pub struct ExpectationStr1<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&str) -> R>>>,
}

impl<R> ExpectationStr1<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&str) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a str) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a str, &'static str>(arg) })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a str, &'static str>(arg) })
        }
    }
}

impl<R> Default for ExpectationStr1<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 1 string argument and 1 slice argument (&str, &[u8])
pub struct ExpectationStrSlice2<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&str, &[u8]) -> R>>>,
}

impl<R> ExpectationStrSlice2<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&str, &[u8]) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a, 'b>(&self, arg1: &'a str, arg2: &'b [u8]) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a str, &'static str>(arg1) }, unsafe {
                std::mem::transmute::<&'b [u8], &'static [u8]>(arg2)
            })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a str, &'static str>(arg1) }, unsafe {
                std::mem::transmute::<&'b [u8], &'static [u8]>(arg2)
            })
        }
    }
}

impl<R> Default for ExpectationStrSlice2<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with mutable slice argument (&mut [u8])
/// Allows closures to write to the buffer
pub struct ExpectationMutSlice1<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&mut [u8]) -> R>>>,
}

impl<R> ExpectationMutSlice1<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&mut [u8]) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a mut [u8]) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            // Extend lifetime to 'static - safe for test closures that don't store the reference
            (expectations[0])(unsafe { std::mem::transmute::<&'a mut [u8], &'static mut [u8]>(arg) })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a mut [u8], &'static mut [u8]>(arg) })
        }
    }
}

impl<R> Default for ExpectationMutSlice1<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with 1 mutable slice argument and closure capture
/// Used for testing sequence behavior where the closure needs to modify state
pub struct ExpectationMutSlice1Seq<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&mut [u8]) -> R>>>,
}

impl<R> ExpectationMutSlice1Seq<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&mut [u8]) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a mut [u8]) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        // Always consume in sequence
        let mut f = expectations.remove(0);
        f(unsafe { std::mem::transmute::<&'a mut [u8], &'static mut [u8]>(arg) })
    }
}

impl<R> Default for ExpectationMutSlice1Seq<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with AesGcmResult reference parameter
/// Allows tests to access the full AesGcmResult structure
pub struct ExpectationAesGcmResult<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&AesGcmResult) -> R>>>,
}

impl<R> ExpectationAesGcmResult<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&AesGcmResult) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a AesGcmResult) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a AesGcmResult, &'static AesGcmResult>(arg) })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a AesGcmResult, &'static AesGcmResult>(arg) })
        }
    }
}

impl<R> Default for ExpectationAesGcmResult<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with AesGcmParam reference parameter
pub struct ExpectationAesGcmParam<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&AesGcmParam) -> R>>>,
}

impl<R> ExpectationAesGcmParam<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&AesGcmParam) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a>(&self, arg: &'a AesGcmParam) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a AesGcmParam, &'static AesGcmParam>(arg) })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a AesGcmParam, &'static AesGcmParam>(arg) })
        }
    }
}

impl<R> Default for ExpectationAesGcmParam<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// Expectation for methods with &[u8] and AesGcmParam parameters
/// Used for aes_gcm_encrypt which needs both plaintext and param
pub struct ExpectationSliceAesGcmParam<R> {
    expectations: RefCell<Vec<Box<dyn FnMut(&[u8], &AesGcmParam) -> R>>>,
}

impl<R> ExpectationSliceAesGcmParam<R> {
    pub fn new() -> Self {
        Self { expectations: RefCell::new(Vec::new()) }
    }

    pub fn returning<F>(&self, f: F)
    where
        F: FnMut(&[u8], &AesGcmParam) -> R + 'static,
    {
        self.expectations.borrow_mut().push(Box::new(f));
    }

    pub fn call<'a, 'b>(&self, arg1: &'a [u8], arg2: &'b AesGcmParam) -> R {
        let mut expectations = self.expectations.borrow_mut();
        if expectations.is_empty() {
            panic!("No expectation set for this method call");
        }
        if expectations.len() == 1 {
            (expectations[0])(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg1) }, unsafe {
                std::mem::transmute::<&'b AesGcmParam, &'static AesGcmParam>(arg2)
            })
        } else {
            let mut f = expectations.remove(0);
            f(unsafe { std::mem::transmute::<&'a [u8], &'static [u8]>(arg1) }, unsafe {
                std::mem::transmute::<&'b AesGcmParam, &'static AesGcmParam>(arg2)
            })
        }
    }
}

impl<R> Default for ExpectationSliceAesGcmParam<R> {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Mock implementations ==============

/// Mock implementation for TimeKeeper trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockTimeKeeper {
    get_system_time: Expectation0<Result<u64, ErrorCode>>,
    get_rtc_time: Expectation0<Result<u64, ErrorCode>>,
    get_ree_time: Expectation0<Result<u64, ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockTimeKeeper {
    pub fn new() -> Self {
        Self {
            get_system_time: Expectation0::new(),
            get_rtc_time: Expectation0::new(),
            get_ree_time: Expectation0::new(),
        }
    }

    pub fn expect_get_system_time(&mut self) -> &mut Expectation0<Result<u64, ErrorCode>> {
        &mut self.get_system_time
    }

    pub fn expect_get_rtc_time(&mut self) -> &mut Expectation0<Result<u64, ErrorCode>> {
        &mut self.get_rtc_time
    }

    pub fn expect_get_ree_time(&mut self) -> &mut Expectation0<Result<u64, ErrorCode>> {
        &mut self.get_ree_time
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::time_keeper::TimeKeeper for MockTimeKeeper {
    fn get_system_time(&self) -> Result<u64, ErrorCode> {
        self.get_system_time.call()
    }

    fn get_rtc_time(&self) -> Result<u64, ErrorCode> {
        self.get_rtc_time.call()
    }

    fn get_ree_time(&self) -> Result<u64, ErrorCode> {
        self.get_ree_time.call()
    }
}

/// Mock implementation for StorageIo trait
/// For simplicity, parameters are ignored
#[cfg(any(test, feature = "test-utils"))]
pub struct MockStorageIo {
    exists: Expectation0<Result<bool, ErrorCode>>,
    read: Expectation0<Result<Vec<u8>, ErrorCode>>,
    write: ExpectationStrSlice2<Result<(), ErrorCode>>,
    delete: Expectation0<Result<(), ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockStorageIo {
    pub fn new() -> Self {
        Self {
            exists: Expectation0::new(),
            read: Expectation0::new(),
            write: ExpectationStrSlice2::new(),
            delete: Expectation0::new(),
        }
    }

    pub fn expect_exists(&mut self) -> &mut Expectation0<Result<bool, ErrorCode>> {
        &mut self.exists
    }

    pub fn expect_read(&mut self) -> &mut Expectation0<Result<Vec<u8>, ErrorCode>> {
        &mut self.read
    }

    pub fn expect_write(&mut self) -> &mut ExpectationStrSlice2<Result<(), ErrorCode>> {
        &mut self.write
    }

    pub fn expect_delete(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::storage_io::StorageIo for MockStorageIo {
    fn exists(&self, _file_name: &str) -> Result<bool, ErrorCode> {
        self.exists.call()
    }

    fn read(&self, _file_name: &str) -> Result<Vec<u8>, ErrorCode> {
        self.read.call()
    }

    fn write(&self, file_name: &str, data: &[u8]) -> Result<(), ErrorCode> {
        self.write.call(file_name, data)
    }

    fn delete(&self, _file_name: &str) -> Result<(), ErrorCode> {
        self.delete.call()
    }
}

/// Mock implementation for MiscManager trait
/// For simplicity, parameters are ignored
#[cfg(any(test, feature = "test-utils"))]
pub struct MockMiscManager {
    get_distribute_key: Expectation0<Result<Vec<u8>, ErrorCode>>,
    set_local_key_pair: Expectation0<Result<(), ErrorCode>>,
    get_local_key_pair: Expectation0<Result<KeyPair, ErrorCode>>,
    set_fwk_pub_key: Expectation0<Result<(), ErrorCode>>,
    get_fwk_pub_key: Expectation0<Result<Vec<u8>, ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockMiscManager {
    pub fn new() -> Self {
        Self {
            get_distribute_key: Expectation0::new(),
            set_local_key_pair: Expectation0::new(),
            get_local_key_pair: Expectation0::new(),
            set_fwk_pub_key: Expectation0::new(),
            get_fwk_pub_key: Expectation0::new(),
        }
    }

    pub fn expect_get_distribute_key(&mut self) -> &mut Expectation0<Result<Vec<u8>, ErrorCode>> {
        &mut self.get_distribute_key
    }

    pub fn expect_set_local_key_pair(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.set_local_key_pair
    }

    pub fn expect_get_local_key_pair(&mut self) -> &mut Expectation0<Result<KeyPair, ErrorCode>> {
        &mut self.get_local_key_pair
    }

    pub fn expect_set_fwk_pub_key(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.set_fwk_pub_key
    }

    pub fn expect_get_fwk_pub_key(&mut self) -> &mut Expectation0<Result<Vec<u8>, ErrorCode>> {
        &mut self.get_fwk_pub_key
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::misc_manager::MiscManager for MockMiscManager {
    fn get_distribute_key(&self, _local_udid: Udid, _peer_udid: Udid) -> Result<Vec<u8>, ErrorCode> {
        self.get_distribute_key.call()
    }

    fn set_local_key_pair(&mut self, _key_pair: KeyPair) -> Result<(), ErrorCode> {
        self.set_local_key_pair.call()
    }

    fn get_local_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        self.get_local_key_pair.call()
    }

    fn set_fwk_pub_key(&mut self, _pub_key: Vec<u8>) -> Result<(), ErrorCode> {
        self.set_fwk_pub_key.call()
    }

    fn get_fwk_pub_key(&self) -> Result<Vec<u8>, ErrorCode> {
        self.get_fwk_pub_key.call()
    }
}

/// Mock implementation for CryptoEngine trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockCryptoEngine {
    generate_ed25519_key_pair: Expectation0<Result<KeyPair, ErrorCode>>,
    ed25519_sign: ExpectationSlice2<Result<Vec<u8>, ErrorCode>>,
    ed25519_verify: ExpectationSlice2<Result<(), ErrorCode>>,
    hmac_sha256: ExpectationSlice2<Result<Vec<u8>, ErrorCode>>,
    sha256: ExpectationSlice1<Result<Vec<u8>, ErrorCode>>,
    secure_random: ExpectationMutSlice1<Result<(), ErrorCode>>,
    secure_random_with_check: Expectation0<Result<(), ErrorCode>>,
    aes_gcm_encrypt: ExpectationSliceAesGcmParam<Result<AesGcmResult, ErrorCode>>,
    aes_gcm_decrypt: ExpectationAesGcmResult<Result<Vec<u8>, ErrorCode>>,
    hkdf: ExpectationSlice2<Result<Vec<u8>, ErrorCode>>,
    p256_ecdh: Expectation0<Result<Vec<u8>, ErrorCode>>,
    x25519_ecdh: Expectation0<Result<Vec<u8>, ErrorCode>>,
    generate_x25519_key_pair: Expectation0<Result<KeyPair, ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockCryptoEngine {
    pub fn new() -> Self {
        Self {
            generate_ed25519_key_pair: Expectation0::new(),
            ed25519_sign: ExpectationSlice2::new(),
            ed25519_verify: ExpectationSlice2::new(),
            hmac_sha256: ExpectationSlice2::new(),
            sha256: ExpectationSlice1::new(),
            secure_random: ExpectationMutSlice1::new(),
            secure_random_with_check: Expectation0::new(),
            aes_gcm_encrypt: ExpectationSliceAesGcmParam::new(),
            aes_gcm_decrypt: ExpectationAesGcmResult::new(),
            hkdf: ExpectationSlice2::new(),
            p256_ecdh: Expectation0::new(),
            x25519_ecdh: Expectation0::new(),
            generate_x25519_key_pair: Expectation0::new(),
        }
    }

    pub fn expect_generate_ed25519_key_pair(&mut self) -> &mut Expectation0<Result<KeyPair, ErrorCode>> {
        &mut self.generate_ed25519_key_pair
    }

    pub fn expect_ed25519_sign(&mut self) -> &mut ExpectationSlice2<Result<Vec<u8>, ErrorCode>> {
        &mut self.ed25519_sign
    }

    pub fn expect_ed25519_verify(&mut self) -> &mut ExpectationSlice2<Result<(), ErrorCode>> {
        &mut self.ed25519_verify
    }

    pub fn expect_hmac_sha256(&mut self) -> &mut ExpectationSlice2<Result<Vec<u8>, ErrorCode>> {
        &mut self.hmac_sha256
    }

    pub fn expect_sha256(&mut self) -> &mut ExpectationSlice1<Result<Vec<u8>, ErrorCode>> {
        &mut self.sha256
    }

    pub fn expect_secure_random(&mut self) -> &mut ExpectationMutSlice1<Result<(), ErrorCode>> {
        &mut self.secure_random
    }

    pub fn expect_secure_random_with_check(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.secure_random_with_check
    }

    pub fn expect_aes_gcm_encrypt(&mut self) -> &mut ExpectationSliceAesGcmParam<Result<AesGcmResult, ErrorCode>> {
        &mut self.aes_gcm_encrypt
    }

    pub fn expect_aes_gcm_decrypt(&mut self) -> &mut ExpectationAesGcmResult<Result<Vec<u8>, ErrorCode>> {
        &mut self.aes_gcm_decrypt
    }

    pub fn expect_hkdf(&mut self) -> &mut ExpectationSlice2<Result<Vec<u8>, ErrorCode>> {
        &mut self.hkdf
    }

    pub fn expect_p256_ecdh(&mut self) -> &mut Expectation0<Result<Vec<u8>, ErrorCode>> {
        &mut self.p256_ecdh
    }

    pub fn expect_x25519_ecdh(&mut self) -> &mut Expectation0<Result<Vec<u8>, ErrorCode>> {
        &mut self.x25519_ecdh
    }

    pub fn expect_generate_x25519_key_pair(&mut self) -> &mut Expectation0<Result<KeyPair, ErrorCode>> {
        &mut self.generate_x25519_key_pair
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::crypto_engine::CryptoEngine for MockCryptoEngine {
    fn generate_ed25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        self.generate_ed25519_key_pair.call()
    }

    fn ed25519_sign(&self, _pri_key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        // Pass empty slice as first param since tests ignore it, pass actual data as second
        self.ed25519_sign.call(&[], data)
    }

    fn ed25519_verify(&self, _pub_key: &[u8], _data: &[u8], _sign: &[u8]) -> Result<(), ErrorCode> {
        self.ed25519_verify.call(&[], &[])
    }

    fn hmac_sha256(&self, _hmac_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.hmac_sha256.call(&[], &[])
    }

    fn sha256(&self, _data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.sha256.call(&[])
    }

    fn secure_random(&self, out_buffer: &mut [u8]) -> Result<(), ErrorCode> {
        self.secure_random.call(out_buffer)
    }

    fn secure_random_with_check(&self, _out_buffer: &mut [u8], _checker: RandomChecker) -> Result<(), ErrorCode> {
        self.secure_random_with_check.call()
    }

    fn aes_gcm_encrypt(&self, plaintext: &[u8], aes_gcm_param: &AesGcmParam) -> Result<AesGcmResult, ErrorCode> {
        self.aes_gcm_encrypt.call(plaintext, aes_gcm_param)
    }

    fn aes_gcm_decrypt(&self, _aes_gcm_param: &AesGcmParam, result: &AesGcmResult) -> Result<Vec<u8>, ErrorCode> {
        self.aes_gcm_decrypt.call(result)
    }

    fn hkdf(&self, _salt: &[u8], _key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.hkdf.call(&[], &[])
    }

    fn p256_ecdh(&self, _key_pair: &KeyPair, _pub_key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.p256_ecdh.call()
    }

    fn x25519_ecdh(&self, _key_pair: &KeyPair, _pub_key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        self.x25519_ecdh.call()
    }

    fn generate_x25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        self.generate_x25519_key_pair.call()
    }
}

/// Mock implementation for EventManager trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockEventManager {
    record_event: Expectation0<()>,
    has_fatal_error: Expectation0<bool>,
    drain_all_events: Expectation0<Vec<Event>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockEventManager {
    pub fn new() -> Self {
        Self {
            record_event: Expectation0::new(),
            has_fatal_error: Expectation0::new(),
            drain_all_events: Expectation0::new(),
        }
    }

    pub fn expect_record_event(&mut self) -> &mut Expectation0<()> {
        &mut self.record_event
    }

    pub fn expect_has_fatal_error(&mut self) -> &mut Expectation0<bool> {
        &mut self.has_fatal_error
    }

    pub fn expect_drain_all_events(&mut self) -> &mut Expectation0<Vec<Event>> {
        &mut self.drain_all_events
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::event_manager::EventManager for MockEventManager {
    fn record_event(&mut self, _event: &crate::traits::event_manager::Event) {
        self.record_event.call()
    }

    fn has_fatal_error(&self) -> bool {
        self.has_fatal_error.call()
    }

    fn drain_all_events(&mut self) -> Vec<Event> {
        self.drain_all_events.call()
    }
}

// ============== Database Manager Mocks ==============

/// Mock implementation for HostDbManager trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockHostDbManager {
    add_device: Expectation0<Result<(), ErrorCode>>,
    get_device: Expectation0<Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode>>,
    get_device_list: Expectation0<Vec<crate::traits::db_manager::CompanionDeviceInfo>>,
    remove_device: Expectation0<Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode>>,
    update_device: Expectation0<Result<(), ErrorCode>>,
    generate_unique_template_id: Expectation0<Result<u64, ErrorCode>>,
    add_token: Expectation0<Result<(), ErrorCode>>,
    get_token: Expectation0<Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode>>,
    remove_token: Expectation0<Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode>>,
    update_token: Expectation0<Result<(), ErrorCode>>,
    read_device_db: Expectation0<Result<(), ErrorCode>>,
    read_device_base_info: Expectation0<Result<crate::traits::db_manager::CompanionDeviceBaseInfo, ErrorCode>>,
    write_device_base_info: Expectation0<Result<(), ErrorCode>>,
    delete_device_base_info: Expectation0<Result<(), ErrorCode>>,
    read_device_capability_info:
        Expectation0<Result<Vec<crate::traits::db_manager::CompanionDeviceCapability>, ErrorCode>>,
    write_device_capability_info: Expectation0<Result<(), ErrorCode>>,
    delete_device_capability_info: Expectation0<Result<(), ErrorCode>>,
    read_device_sk: Expectation0<Result<Vec<crate::traits::db_manager::CompanionDeviceSk>, ErrorCode>>,
    write_device_sk: Expectation0<Result<(), ErrorCode>>,
    delete_device_sk: Expectation0<Result<(), ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockHostDbManager {
    pub fn new() -> Self {
        Self {
            add_device: Expectation0::new(),
            get_device: Expectation0::new(),
            get_device_list: Expectation0::new(),
            remove_device: Expectation0::new(),
            update_device: Expectation0::new(),
            generate_unique_template_id: Expectation0::new(),
            add_token: Expectation0::new(),
            get_token: Expectation0::new(),
            remove_token: Expectation0::new(),
            update_token: Expectation0::new(),
            read_device_db: Expectation0::new(),
            read_device_base_info: Expectation0::new(),
            write_device_base_info: Expectation0::new(),
            delete_device_base_info: Expectation0::new(),
            read_device_capability_info: Expectation0::new(),
            write_device_capability_info: Expectation0::new(),
            delete_device_capability_info: Expectation0::new(),
            read_device_sk: Expectation0::new(),
            write_device_sk: Expectation0::new(),
            delete_device_sk: Expectation0::new(),
        }
    }

    pub fn expect_add_device(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.add_device
    }
    pub fn expect_get_device(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode>> {
        &mut self.get_device
    }
    pub fn expect_get_device_list(&mut self) -> &mut Expectation0<Vec<crate::traits::db_manager::CompanionDeviceInfo>> {
        &mut self.get_device_list
    }
    pub fn expect_remove_device(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode>> {
        &mut self.remove_device
    }
    pub fn expect_update_device(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.update_device
    }
    pub fn expect_generate_unique_template_id(&mut self) -> &mut Expectation0<Result<u64, ErrorCode>> {
        &mut self.generate_unique_template_id
    }
    pub fn expect_add_token(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.add_token
    }
    pub fn expect_get_token(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode>> {
        &mut self.get_token
    }
    pub fn expect_remove_token(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode>> {
        &mut self.remove_token
    }
    pub fn expect_update_token(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.update_token
    }
    pub fn expect_read_device_db(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.read_device_db
    }
    pub fn expect_read_device_base_info(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::CompanionDeviceBaseInfo, ErrorCode>> {
        &mut self.read_device_base_info
    }
    pub fn expect_write_device_base_info(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.write_device_base_info
    }
    pub fn expect_delete_device_base_info(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete_device_base_info
    }
    pub fn expect_read_device_capability_info(
        &mut self,
    ) -> &mut Expectation0<Result<Vec<crate::traits::db_manager::CompanionDeviceCapability>, ErrorCode>> {
        &mut self.read_device_capability_info
    }
    pub fn expect_write_device_capability_info(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.write_device_capability_info
    }
    pub fn expect_delete_device_capability_info(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete_device_capability_info
    }
    pub fn expect_read_device_sk(
        &mut self,
    ) -> &mut Expectation0<Result<Vec<crate::traits::db_manager::CompanionDeviceSk>, ErrorCode>> {
        &mut self.read_device_sk
    }
    pub fn expect_write_device_sk(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.write_device_sk
    }
    pub fn expect_delete_device_sk(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete_device_sk
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::host_db_manager::HostDbManager for MockHostDbManager {
    fn add_device(
        &mut self,
        _device_info: &crate::traits::db_manager::CompanionDeviceInfo,
        _base_info: &crate::traits::db_manager::CompanionDeviceBaseInfo,
        _capability_info: &[crate::traits::db_manager::CompanionDeviceCapability],
        _sk_info: &[crate::traits::db_manager::CompanionDeviceSk],
    ) -> Result<(), ErrorCode> {
        self.add_device.call()
    }
    fn get_device(&self, _template_id: u64) -> Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode> {
        self.get_device.call()
    }
    fn get_device_list(
        &self,
        _filter: crate::traits::host_db_manager::CompanionDeviceFilter,
    ) -> Vec<crate::traits::db_manager::CompanionDeviceInfo> {
        self.get_device_list.call()
    }
    fn remove_device(
        &mut self,
        _template_id: u64,
    ) -> Result<crate::traits::db_manager::CompanionDeviceInfo, ErrorCode> {
        self.remove_device.call()
    }
    fn update_device(
        &mut self,
        _device_info: &crate::traits::db_manager::CompanionDeviceInfo,
    ) -> Result<(), ErrorCode> {
        self.update_device.call()
    }
    fn generate_unique_template_id(&self) -> Result<u64, ErrorCode> {
        self.generate_unique_template_id.call()
    }
    fn add_token(&mut self, _token: &crate::traits::db_manager::CompanionTokenInfo) -> Result<(), ErrorCode> {
        self.add_token.call()
    }
    fn get_token(
        &self,
        _template_id: u64,
        _device_type: DeviceType,
    ) -> Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode> {
        self.get_token.call()
    }
    fn remove_token(
        &mut self,
        _template_id: u64,
        _device_type: DeviceType,
    ) -> Result<crate::traits::db_manager::CompanionTokenInfo, ErrorCode> {
        self.remove_token.call()
    }
    fn update_token(&mut self, _device_info: &crate::traits::db_manager::CompanionTokenInfo) -> Result<(), ErrorCode> {
        self.update_token.call()
    }
    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        self.read_device_db.call()
    }
    fn read_device_base_info(
        &self,
        _template_id: u64,
    ) -> Result<crate::traits::db_manager::CompanionDeviceBaseInfo, ErrorCode> {
        self.read_device_base_info.call()
    }
    fn write_device_base_info(
        &self,
        _template_id: u64,
        _base_info: &crate::traits::db_manager::CompanionDeviceBaseInfo,
    ) -> Result<(), ErrorCode> {
        self.write_device_base_info.call()
    }
    fn delete_device_base_info(&self, _template_id: u64) -> Result<(), ErrorCode> {
        self.delete_device_base_info.call()
    }
    fn read_device_capability_info(
        &self,
        _template_id: u64,
    ) -> Result<Vec<crate::traits::db_manager::CompanionDeviceCapability>, ErrorCode> {
        self.read_device_capability_info.call()
    }
    fn write_device_capability_info(
        &self,
        _template_id: u64,
        _capability_info: &[crate::traits::db_manager::CompanionDeviceCapability],
    ) -> Result<(), ErrorCode> {
        self.write_device_capability_info.call()
    }
    fn delete_device_capability_info(&self, _template_id: u64) -> Result<(), ErrorCode> {
        self.delete_device_capability_info.call()
    }
    fn read_device_sk(
        &self,
        _template_id: u64,
    ) -> Result<Vec<crate::traits::db_manager::CompanionDeviceSk>, ErrorCode> {
        self.read_device_sk.call()
    }
    fn write_device_sk(
        &self,
        _template_id: u64,
        _sk_info: &[crate::traits::db_manager::CompanionDeviceSk],
    ) -> Result<(), ErrorCode> {
        self.write_device_sk.call()
    }
    fn delete_device_sk(&self, _template_id: u64) -> Result<(), ErrorCode> {
        self.delete_device_sk.call()
    }
}

/// Mock implementation for CompanionDbManager trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockCompanionDbManager {
    add_device: Expectation0<Result<(), ErrorCode>>,
    get_device_by_binding_id: Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>>,
    get_device_by_device_key: Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>>,
    remove_device: Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>>,
    update_device: Expectation0<Result<(), ErrorCode>>,
    generate_unique_binding_id: Expectation0<Result<i32, ErrorCode>>,
    read_device_db: Expectation0<Result<(), ErrorCode>>,
    read_device_token: Expectation0<Result<crate::traits::db_manager::HostTokenInfo, ErrorCode>>,
    write_device_token: Expectation0<Result<(), ErrorCode>>,
    delete_device_token: Expectation0<Result<(), ErrorCode>>,
    is_device_token_valid: Expectation0<Result<bool, ErrorCode>>,
    read_device_sk: Expectation0<Result<crate::traits::db_manager::HostDeviceSk, ErrorCode>>,
    write_device_sk: Expectation0<Result<(), ErrorCode>>,
    delete_device_sk: Expectation0<Result<(), ErrorCode>>,
    get_device_list: Expectation0<Vec<crate::traits::db_manager::HostDeviceInfo>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockCompanionDbManager {
    pub fn new() -> Self {
        Self {
            add_device: Expectation0::new(),
            get_device_by_binding_id: Expectation0::new(),
            get_device_by_device_key: Expectation0::new(),
            remove_device: Expectation0::new(),
            update_device: Expectation0::new(),
            generate_unique_binding_id: Expectation0::new(),
            read_device_db: Expectation0::new(),
            read_device_token: Expectation0::new(),
            write_device_token: Expectation0::new(),
            delete_device_token: Expectation0::new(),
            is_device_token_valid: Expectation0::new(),
            read_device_sk: Expectation0::new(),
            write_device_sk: Expectation0::new(),
            delete_device_sk: Expectation0::new(),
            get_device_list: Expectation0::new(),
        }
    }

    pub fn expect_add_device(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.add_device
    }
    pub fn expect_get_device_by_binding_id(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>> {
        &mut self.get_device_by_binding_id
    }
    pub fn expect_get_device_by_device_key(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>> {
        &mut self.get_device_by_device_key
    }
    pub fn expect_remove_device(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode>> {
        &mut self.remove_device
    }
    pub fn expect_update_device(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.update_device
    }
    pub fn expect_generate_unique_binding_id(&mut self) -> &mut Expectation0<Result<i32, ErrorCode>> {
        &mut self.generate_unique_binding_id
    }
    pub fn expect_read_device_db(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.read_device_db
    }
    pub fn expect_read_device_token(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::HostTokenInfo, ErrorCode>> {
        &mut self.read_device_token
    }
    pub fn expect_write_device_token(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.write_device_token
    }
    pub fn expect_delete_device_token(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete_device_token
    }
    pub fn expect_is_device_token_valid(&mut self) -> &mut Expectation0<Result<bool, ErrorCode>> {
        &mut self.is_device_token_valid
    }
    pub fn expect_read_device_sk(
        &mut self,
    ) -> &mut Expectation0<Result<crate::traits::db_manager::HostDeviceSk, ErrorCode>> {
        &mut self.read_device_sk
    }
    pub fn expect_write_device_sk(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.write_device_sk
    }
    pub fn expect_delete_device_sk(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.delete_device_sk
    }
    pub fn expect_get_device_list(&mut self) -> &mut Expectation0<Vec<crate::traits::db_manager::HostDeviceInfo>> {
        &mut self.get_device_list
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::companion_db_manager::CompanionDbManager for MockCompanionDbManager {
    fn add_device(
        &mut self,
        _device_info: &crate::traits::db_manager::HostDeviceInfo,
        _sk_info: &crate::traits::db_manager::HostDeviceSk,
    ) -> Result<(), ErrorCode> {
        self.add_device.call()
    }
    fn get_device_by_binding_id(
        &self,
        _binding_id: i32,
    ) -> Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode> {
        self.get_device_by_binding_id.call()
    }
    fn get_device_by_device_key(
        &self,
        _user_id: i32,
        _device_key: &crate::traits::db_manager::DeviceKey,
    ) -> Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode> {
        self.get_device_by_device_key.call()
    }
    fn remove_device(&mut self, _binding_id: i32) -> Result<crate::traits::db_manager::HostDeviceInfo, ErrorCode> {
        self.remove_device.call()
    }
    fn update_device(&mut self, _device_info: &crate::traits::db_manager::HostDeviceInfo) -> Result<(), ErrorCode> {
        self.update_device.call()
    }
    fn generate_unique_binding_id(&self) -> Result<i32, ErrorCode> {
        self.generate_unique_binding_id.call()
    }
    fn read_device_db(&mut self) -> Result<(), ErrorCode> {
        self.read_device_db.call()
    }
    fn read_device_token(&self, _binding_id: i32) -> Result<crate::traits::db_manager::HostTokenInfo, ErrorCode> {
        self.read_device_token.call()
    }
    fn write_device_token(
        &self,
        _binding_id: i32,
        _token: &crate::traits::db_manager::HostTokenInfo,
    ) -> Result<(), ErrorCode> {
        self.write_device_token.call()
    }
    fn delete_device_token(&self, _binding_id: i32) -> Result<(), ErrorCode> {
        self.delete_device_token.call()
    }
    fn is_device_token_valid(&self, _binding_id: i32) -> Result<bool, ErrorCode> {
        self.is_device_token_valid.call()
    }
    fn read_device_sk(&self, _binding_id: i32) -> Result<crate::traits::db_manager::HostDeviceSk, ErrorCode> {
        self.read_device_sk.call()
    }
    fn write_device_sk(
        &self,
        _binding_id: i32,
        _sk_info: &crate::traits::db_manager::HostDeviceSk,
    ) -> Result<(), ErrorCode> {
        self.write_device_sk.call()
    }
    fn delete_device_sk(&self, _binding_id: i32) -> Result<(), ErrorCode> {
        self.delete_device_sk.call()
    }
    fn get_device_list(&self, _user_id: i32) -> Vec<crate::traits::db_manager::HostDeviceInfo> {
        self.get_device_list.call()
    }
}

// ============== Request Manager Mocks ==============

/// Mock implementation for RequestManager trait
#[cfg(any(test, feature = "test-utils"))]
pub struct MockRequestManager {
    add_request: Expectation0<Result<(), ErrorCode>>,
    remove_request: Expectation0<Result<Box<crate::traits::request_manager::DynRequest>, ErrorCode>>,
    // Internal storage for get_request to return &mut reference
    stored_request: RefCell<Option<Box<crate::traits::request_manager::DynRequest>>>,
    get_request_result: Cell<Result<(), ErrorCode>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockRequestManager {
    pub fn new() -> Self {
        Self {
            add_request: Expectation0::new(),
            remove_request: Expectation0::new(),
            stored_request: RefCell::new(None),
            get_request_result: Cell::new(Ok(())),
        }
    }

    pub fn expect_add_request(&mut self) -> &mut Expectation0<Result<(), ErrorCode>> {
        &mut self.add_request
    }

    pub fn expect_remove_request(
        &mut self,
    ) -> &mut Expectation0<Result<Box<crate::traits::request_manager::DynRequest>, ErrorCode>> {
        &mut self.remove_request
    }

    /// Set the result for get_request call
    /// Returns Ok(()) to return the stored request, or Err(code) to return an error
    pub fn expect_get_request(&mut self, result: Result<(), ErrorCode>) {
        self.get_request_result.set(result);
    }

    /// Set a specific request to be returned by get_request
    pub fn set_get_request_return(&mut self, request: Option<Box<crate::traits::request_manager::DynRequest>>) {
        *self.stored_request.borrow_mut() = request;
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl crate::traits::request_manager::RequestManager for MockRequestManager {
    fn add_request(&mut self, _request: Box<crate::traits::request_manager::DynRequest>) -> Result<(), ErrorCode> {
        self.add_request.call()
    }

    fn remove_request(
        &mut self,
        _request_id: i32,
    ) -> Result<Box<crate::traits::request_manager::DynRequest>, ErrorCode> {
        self.remove_request.call()
    }

    fn get_request(&mut self, _request_id: i32) -> Result<&mut crate::traits::request_manager::DynRequest, ErrorCode> {
        // Check if we should return error
        self.get_request_result.get()?;

        // Get raw pointer to stored request
        // SAFETY: In test context, we assume single-threaded usage and proper lifecycle.
        // The Mock object outlives the returned reference.
        let raw_ptr = self
            .stored_request
            .borrow()
            .as_ref()
            .map(|r| r.as_ref() as *const crate::traits::request_manager::DynRequest)
            .ok_or(ErrorCode::NotFound)? as *mut crate::traits::request_manager::DynRequest;

        unsafe { Ok(&mut *raw_ptr) }
    }
}
