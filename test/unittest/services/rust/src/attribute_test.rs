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

use rust::common::constants::ErrorCode;
use rust::{log_e, log_i, p, Vec};
extern rust alloc;
use rust::utils::parcel::Parcel;
use rust::String;
use alloc::{collections::BTreeMap, vec};
use core::mem;
use serde_json;
use rust::ut_registry_guard;
use rust::utils::attribute;

#[test]
fn attribute_key_test() {
    let _guard = ut_registry_guard!();
    log_i!("attribute_key_test start");

    assert_eq!(AttributeKey::try_from(100001).unwrap(), AttributeKey::AttrResultCode);
    assert_eq!(AttributeKey::try_from(100004).unwrap(), AttributeKey::AttrSignature);
    assert_eq!(AttributeKey::try_from(100006).unwrap(), AttributeKey::AttrTemplateId);
    assert_eq!(AttributeKey::try_from(100007).unwrap(), AttributeKey::AttrTemplateIdList);
    assert_eq!(AttributeKey::try_from(100009).unwrap(), AttributeKey::AttrRemainAttempts);
    assert_eq!(AttributeKey::try_from(100010).unwrap(), AttributeKey::AttrLockoutDuration);
    assert_eq!(AttributeKey::try_from(100014).unwrap(), AttributeKey::AttrScheduleId);
    assert_eq!(AttributeKey::try_from(100020).unwrap(), AttributeKey::AttrData);
    assert_eq!(AttributeKey::try_from(100021).unwrap(), AttributeKey::AttrPinSubType);
    assert_eq!(AttributeKey::try_from(100023).unwrap(), AttributeKey::AttrProperyMode);
    assert_eq!(AttributeKey::try_from(100024).unwrap(), AttributeKey::AttrType);
    assert_eq!(AttributeKey::try_from(100029).unwrap(), AttributeKey::AttrCapabilityLevel);
    assert_eq!(AttributeKey::try_from(100035).unwrap(), AttributeKey::AttrNeedRootSecret);
    assert_eq!(AttributeKey::try_from(100041).unwrap(), AttributeKey::AttrUserId);
    assert_eq!(AttributeKey::try_from(100042).unwrap(), AttributeKey::AttrToken);
    assert_eq!(AttributeKey::try_from(100044).unwrap(), AttributeKey::AttrEsl);
    assert_eq!(AttributeKey::try_from(100065).unwrap(), AttributeKey::AttrPublicKey);
    assert_eq!(AttributeKey::try_from(100066).unwrap(), AttributeKey::AttrChallenge);
    assert_eq!(AttributeKey::try_from(100088).unwrap(), AttributeKey::AttrAuthTrustLevel);
    assert_eq!(AttributeKey::try_from(300001).unwrap(), AttributeKey::AttrMessage);
    assert_eq!(AttributeKey::try_from(300002).unwrap(), AttributeKey::AttrAlgoList);
    assert_eq!(AttributeKey::try_from(300003).unwrap(), AttributeKey::AttrCapabilityList);
    assert_eq!(AttributeKey::try_from(300004).unwrap(), AttributeKey::AttrDeviceId);
    assert_eq!(AttributeKey::try_from(300005).unwrap(), AttributeKey::AttrSalt);
    assert_eq!(AttributeKey::try_from(300006).unwrap(), AttributeKey::AttrTag);
    assert_eq!(AttributeKey::try_from(300007).unwrap(), AttributeKey::AttrIv);
    assert_eq!(AttributeKey::try_from(300008).unwrap(), AttributeKey::AttrEncryptData);
    assert_eq!(AttributeKey::try_from(300009).unwrap(), AttributeKey::AttrTrackAbilityLevel);
    assert_eq!(AttributeKey::try_from(300010).unwrap(), AttributeKey::AttrHmac);

    let attribute_key = AttributeKey::AttrRoot;
    println!("{:?}", attribute_key);
}

#[test]
fn try_from_bytes_test() {
    let _guard = ut_registry_guard!();
    log_i!("try_from_bytes_test start");

    assert_eq!(AttributeKey::try_from_bytes(&[]), Err(ErrorCode::BadParam));

    let invalid_key: i32 = 999999;
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let mut parcel = Parcel::new();
    parcel.write_i32_le(invalid_key);
    parcel.write_u32_le(data.len() as u32);
    parcel.write_bytes(&data);

    let attribute = Attribute::try_from_bytes(parcel.as_slice()).unwrap();
    assert_eq!(attribute.map.len(), 0);
}

#[test]
fn get_fail_test() {
    let _guard = ut_registry_guard!();
    log_i!("get_fail_test start");

    let mut attribute = Attribute::new();
    assert_eq!(attribute.get_u32(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));
    assert_eq!(attribute.get_attributes(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));

    attribute.set_u8_slice(AttributeKey::AttrRoot, &[0x01, 0x02]);
    assert_eq!(attribute.get_u32(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));
    assert_eq!(attribute.get_i32(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));
    assert_eq!(attribute.get_u64(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));
    assert_eq!(attribute.get_u64_vec(AttributeKey::AttrRoot), Err(ErrorCode::GeneralError));
}

#[test]
fn fill_u8_slice_test() {
    let _guard = ut_registry_guard!();
    log_i!("fill_u8_slice_test start");

    let mut attribute = Attribute::new();
    let mut buffer = [0u8; 4];
    attribute.set_u8_slice(AttributeKey::AttrRoot, &[0x01, 0x02]);
    assert_eq!(attribute.fill_u8_slice(AttributeKey::AttrRoot, &mut buffer), Err(ErrorCode::GeneralError));
}

#[test]
fn get_keys_test() {
    let _guard = ut_registry_guard!();
    log_i!("get_keys_test start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrRoot, &[0x01, 0x02]);
    assert_eq!(attribute.get_keys(), vec![AttributeKey::AttrRoot]);
}