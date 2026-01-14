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

use crate::common::constants::ErrorCode;
use crate::log_i;
use crate::ut_registry_guard;
use crate::utils::parcel::Parcel;
use crate::utils::{Attribute, AttributeKey};

#[test]
fn attribute_key_test() {
    let _guard = ut_registry_guard!();
    log_i!("attribute_key_test start");

    assert_eq!(AttributeKey::try_from(100000).unwrap(), AttributeKey::AttrRoot);
    assert_eq!(AttributeKey::try_from(100001).unwrap(), AttributeKey::AttrResultCode);
    assert_eq!(AttributeKey::try_from(100004).unwrap(), AttributeKey::AttrSignature);
    assert_eq!(AttributeKey::try_from(100006).unwrap(), AttributeKey::AttrTemplateId);
    assert_eq!(AttributeKey::try_from(100007).unwrap(), AttributeKey::AttrTemplateIdList);
    assert_eq!(AttributeKey::try_from(100009).unwrap(), AttributeKey::AttrRemainAttempts);
    assert_eq!(AttributeKey::try_from(100010).unwrap(), AttributeKey::AttrLockoutDuration);
    assert_eq!(AttributeKey::try_from(100014).unwrap(), AttributeKey::AttrScheduleId);
    assert_eq!(AttributeKey::try_from(100020).unwrap(), AttributeKey::AttrData);
    assert_eq!(AttributeKey::try_from(100021).unwrap(), AttributeKey::AttrPinSubType);
    assert_eq!(AttributeKey::try_from(100023).unwrap(), AttributeKey::AttrPropertyMode);
    assert_eq!(AttributeKey::try_from(100024).unwrap(), AttributeKey::AttrType);
    assert_eq!(AttributeKey::try_from(100029).unwrap(), AttributeKey::AttrCapabilityLevel);
    assert_eq!(AttributeKey::try_from(100041).unwrap(), AttributeKey::AttrUserId);
    assert_eq!(AttributeKey::try_from(100042).unwrap(), AttributeKey::AttrToken);
    assert_eq!(AttributeKey::try_from(100044).unwrap(), AttributeKey::AttrEsl);
    assert_eq!(AttributeKey::try_from(100065).unwrap(), AttributeKey::AttrPublicKey);
    assert_eq!(AttributeKey::try_from(100066).unwrap(), AttributeKey::AttrChallenge);
    assert_eq!(AttributeKey::try_from(100089).unwrap(), AttributeKey::AttrAuthTrustLevel);
    assert_eq!(AttributeKey::try_from(300001).unwrap(), AttributeKey::AttrMessage);
    assert_eq!(AttributeKey::try_from(300002).unwrap(), AttributeKey::AttrProtocolList);
    assert_eq!(AttributeKey::try_from(300003).unwrap(), AttributeKey::AttrAlgoList);
    assert_eq!(AttributeKey::try_from(300004).unwrap(), AttributeKey::AttrCapabilityList);
    assert_eq!(AttributeKey::try_from(300005).unwrap(), AttributeKey::AttrDeviceId);
    assert_eq!(AttributeKey::try_from(300006).unwrap(), AttributeKey::AttrSalt);
    assert_eq!(AttributeKey::try_from(300007).unwrap(), AttributeKey::AttrTag);
    assert_eq!(AttributeKey::try_from(300008).unwrap(), AttributeKey::AttrIv);
    assert_eq!(AttributeKey::try_from(300009).unwrap(), AttributeKey::AttrEncryptData);
    assert_eq!(AttributeKey::try_from(300010).unwrap(), AttributeKey::AttrTrackAbilityLevel);
    assert_eq!(AttributeKey::try_from(300011).unwrap(), AttributeKey::AttrHmac);
    assert_eq!(AttributeKey::try_from(0), Err(ErrorCode::GeneralError));
}

#[test]
fn try_from_bytes_fail_test() {
    let _guard = ut_registry_guard!();
    log_i!("try_from_bytes_fail_test start");

    assert_eq!(Attribute::try_from_bytes(&[]), Err(ErrorCode::BadParam));
    let mut parcel = Parcel::new();
    assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::BadParam));
    parcel.write_i32_le(0);
    assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::ReadParcelError));
    parcel.write_u32_le(4);
    assert_eq!(Attribute::try_from_bytes(parcel.as_slice()), Err(ErrorCode::ReadParcelError));
    parcel.write_bytes(&[1, 2, 3, 4]);
    assert!(Attribute::try_from_bytes(parcel.as_slice()).is_ok());
}

#[test]
fn try_from_bytes_success_test() {
    let _guard = ut_registry_guard!();
    log_i!("try_from_bytes_success_test start");

    let mut parcel = Parcel::new();
    parcel.write_i32_le(AttributeKey::AttrRoot as i32);
    parcel.write_u32_le(4);
    parcel.write_bytes(&[1, 2, 3, 4]);
    assert!(Attribute::try_from_bytes(parcel.as_slice()).is_ok());
}

#[test]
fn to_bytes_test() {
    let _guard = ut_registry_guard!();
    log_i!("to_bytes_test start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    assert!(attribute.to_bytes().is_ok());
}

#[test]
fn u16_test() {
    let _guard = ut_registry_guard!();
    log_i!("u16_test start");

    let mut attribute = Attribute::new();
    assert_eq!(attribute.get_u16(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    assert_eq!(attribute.get_u16(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u16(AttributeKey::AttrResultCode, 0);
    assert!(attribute.get_u16(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u32_test() {
    let _guard = ut_registry_guard!();
    log_i!("u32_test start");

    let mut attribute = Attribute::new();
    assert_eq!(attribute.get_u32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u16(AttributeKey::AttrResultCode, 0);
    assert_eq!(attribute.get_u32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    assert!(attribute.get_u32(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn i32_test() {
    let _guard = ut_registry_guard!();
    log_i!("i32_test start");

    let mut attribute = Attribute::new();
    assert_eq!(attribute.get_i32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u16(AttributeKey::AttrResultCode, 0);
    assert_eq!(attribute.get_i32(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_i32(AttributeKey::AttrResultCode, 0);
    assert!(attribute.get_i32(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u64_test() {
    let _guard = ut_registry_guard!();
    log_i!("u64_test start");

    let mut attribute = Attribute::new();
    assert_eq!(attribute.get_u64(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u16(AttributeKey::AttrResultCode, 0);
    assert_eq!(attribute.get_u64(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    attribute.set_u64(AttributeKey::AttrResultCode, 0);
    assert!(attribute.get_u64(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u8_slice_test() {
    let _guard = ut_registry_guard!();
    log_i!("u8_slice_test start");

    let mut attribute: Attribute = Attribute::new();
    assert_eq!(attribute.get_u8_slice(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));
    assert_eq!(attribute.get_u8_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    assert_eq!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 0]), Err(ErrorCode::GeneralError));
    attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
    assert_eq!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 0]), Err(ErrorCode::GeneralError));
    assert!(attribute.fill_u8_slice(AttributeKey::AttrResultCode, &mut [0u8; 1]).is_ok());

    assert!(attribute.get_u8_slice(AttributeKey::AttrResultCode).is_ok());
    assert!(attribute.get_u8_vec(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u64_slice_test() {
    let _guard = ut_registry_guard!();
    log_i!("u64_slice_test start");

    let mut attribute: Attribute = Attribute::new();
    assert_eq!(attribute.get_u64_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
    assert_eq!(attribute.get_u64_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_u64_slice(AttributeKey::AttrResultCode, &[0u64; 1]);
    assert!(attribute.get_u64_vec(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u16_slice_test() {
    let _guard = ut_registry_guard!();
    log_i!("u16_slice_test start");

    let mut attribute: Attribute = Attribute::new();
    assert_eq!(attribute.get_u16_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
    assert_eq!(attribute.get_u16_vec(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_u16_slice(AttributeKey::AttrResultCode, &[0u16; 1]);
    assert!(attribute.get_u16_vec(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn u8_slices_test() {
    let _guard = ut_registry_guard!();
    log_i!("u8_slices_test start");

    let mut attribute: Attribute = Attribute::new();
    assert_eq!(attribute.get_u8_vecs(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 1]);
    assert_eq!(attribute.get_u8_vecs(AttributeKey::AttrResultCode), Err(ErrorCode::ReadParcelError));
    attribute.set_u8_slice(AttributeKey::AttrResultCode, &[0u8; 4]);
    assert!(attribute.get_u8_vecs(AttributeKey::AttrResultCode).is_ok());

    attribute.set_u8_slices(AttributeKey::AttrResultCode, &[&[0u8]]);
    assert!(attribute.get_u8_vecs(AttributeKey::AttrResultCode).is_ok());
}

#[test]
fn string_test() {
    let _guard = ut_registry_guard!();
    log_i!("string_test start");

    let mut attribute: Attribute = Attribute::new();
    assert_eq!(attribute.get_string(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    let sparkle_heart = [0u8, 159u8, 146u8, 150u8];
    attribute.set_u8_slice(AttributeKey::AttrResultCode, &sparkle_heart);
    assert_eq!(attribute.get_string(AttributeKey::AttrResultCode), Err(ErrorCode::GeneralError));

    attribute.set_string(AttributeKey::AttrResultCode, String::from("Hello"));
    assert!(attribute.get_string(AttributeKey::AttrResultCode).is_ok());
}
