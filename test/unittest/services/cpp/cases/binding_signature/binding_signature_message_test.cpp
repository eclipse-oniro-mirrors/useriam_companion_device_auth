/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "binding_signature_message.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "attributes.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
// P-256 DER signature upper bound; enforced by the Rust crypto layer, message layer does not clamp.
constexpr size_t BINDING_SIGNATURE_P256_DER_MAX_LEN = 72;

class BindingSignatureMessageTest : public Test {
public:
protected:
    std::vector<uint8_t> challenge_ = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    // ECDSA signatures are variable length; the fixture uses the valid maximum.
    std::vector<uint8_t> signature_ = std::vector<uint8_t>(BINDING_SIGNATURE_P256_DER_MAX_LEN, 0xCD);
};
} // namespace

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeRequestEncodeDecode,
    TestSize.Level0)
{
    GetBindingSignatureChallengeRequest request = {};
    request.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    request.hostDeviceKey.deviceId = "host_device_id";
    request.hostDeviceKey.deviceUserId = 100;
    request.hostDeviceKey.deviceSubProfileId = 1;
    request.companionUserKey = UserKey { 200, 2 };

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeRequest(request, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    auto decodeOpt = DecodeGetBindingSignatureChallengeRequest(attributes);
    EXPECT_TRUE(decodeOpt.has_value());
    EXPECT_EQ(decodeOpt->hostDeviceKey.deviceUserId, 100);
    EXPECT_EQ(decodeOpt->hostDeviceKey.deviceSubProfileId, 1);
    EXPECT_EQ(decodeOpt->hostDeviceKey.deviceId, "host_device_id");
    EXPECT_TRUE(decodeOpt->companionUserKey.has_value());
    EXPECT_EQ(decodeOpt->companionUserKey->userId, 200);
    EXPECT_EQ(decodeOpt->companionUserKey->subProfileId, 2);
    EXPECT_EQ(decodeOpt->connectionName, "test_connection");
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeRequestDecodeMissingField,
    TestSize.Level0)
{
    Attributes attributes = {};
    auto decodeOpt = DecodeGetBindingSignatureChallengeRequest(attributes);
    EXPECT_FALSE(decodeOpt.has_value());
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeRequestTargetOmitted,
    TestSize.Level0)
{
    GetBindingSignatureChallengeRequest request = {};
    request.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    request.hostDeviceKey.deviceId = "host_device_id";
    request.hostDeviceKey.deviceUserId = 100;
    request.hostDeviceKey.deviceSubProfileId = 1;
    request.companionUserKey = std::nullopt;

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeRequest(request, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    auto decodeOpt = DecodeGetBindingSignatureChallengeRequest(attributes);
    EXPECT_TRUE(decodeOpt.has_value());
    EXPECT_FALSE(decodeOpt->companionUserKey.has_value());
}

HWTEST_F(BindingSignatureMessageTest,
    BindingSignatureMessageTest_GetBindingSignatureChallengeRequestTargetPartiallyOmitted, TestSize.Level0)
{
    GetBindingSignatureChallengeRequest request = {};
    request.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    request.hostDeviceKey.deviceId = "host_device_id";
    request.hostDeviceKey.deviceUserId = 100;

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeRequest(request, attributes);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    // only the target user id is present, the sub profile id is missing
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 200);

    auto decodeOpt = DecodeGetBindingSignatureChallengeRequest(attributes);
    EXPECT_TRUE(decodeOpt.has_value());
    EXPECT_FALSE(decodeOpt->companionUserKey.has_value());
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeReplyEncodeDecode,
    TestSize.Level0)
{
    GetBindingSignatureChallengeReply reply = {};
    reply.result = ResultCode::SUCCESS;
    reply.companionUserKey = UserKey { 200, 2 };
    reply.challenge = challenge_;

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeReply(reply, attributes);

    auto decodeOpt = DecodeGetBindingSignatureChallengeReply(attributes);
    EXPECT_TRUE(decodeOpt.has_value());
    EXPECT_EQ(decodeOpt->result, ResultCode::SUCCESS);
    EXPECT_EQ(decodeOpt->companionUserKey.userId, 200);
    EXPECT_EQ(decodeOpt->companionUserKey.subProfileId, 2);
    EXPECT_EQ(decodeOpt->challenge, challenge_);
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeReplySubProfileIdMissing,
    TestSize.Level0)
{
    GetBindingSignatureChallengeReply reply = {};
    reply.result = ResultCode::SUCCESS;
    reply.companionUserKey = UserKey { 200, 2 };
    reply.challenge = challenge_;

    // success reply missing the sub profile id is rejected
    Attributes attributes = {};
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, reply.companionUserKey.userId);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, reply.challenge);

    auto decodeOpt = DecodeGetBindingSignatureChallengeReply(attributes);
    EXPECT_FALSE(decodeOpt.has_value());
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeReplyErrorHasNoChallenge,
    TestSize.Level0)
{
    GetBindingSignatureChallengeReply reply = {};
    reply.result = ResultCode::GENERAL_ERROR;

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeReply(reply, attributes);

    auto decodeOpt = DecodeGetBindingSignatureChallengeReply(attributes);
    EXPECT_TRUE(decodeOpt.has_value());
    EXPECT_EQ(decodeOpt->result, ResultCode::GENERAL_ERROR);
    EXPECT_TRUE(decodeOpt->challenge.empty());
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_GetBindingSignatureChallengeReplyChallengeLenMismatch,
    TestSize.Level0)
{
    GetBindingSignatureChallengeReply reply = {};
    reply.result = ResultCode::SUCCESS;
    reply.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN / 2, 0x01);

    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeReply(reply, attributes);

    auto decodeOpt = DecodeGetBindingSignatureChallengeReply(attributes);
    EXPECT_FALSE(decodeOpt.has_value());
}

HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_BindingSignatureAttributesAttachDecode,
    TestSize.Level0)
{
    Attributes attributes = {};
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    AttachBindingSignatureAttributes(challenge_, signature_, attributes);

    EXPECT_TRUE(HasBindingSignatureAttributes(attributes));
    auto bindingSignatureOpt = DecodeBindingSignatureAttributes(attributes);
    EXPECT_TRUE(bindingSignatureOpt.has_value());
    EXPECT_EQ(bindingSignatureOpt->challenge, challenge_);
    EXPECT_EQ(bindingSignatureOpt->signature, signature_);
}

// ECDSA signatures are variable length: any non-empty signature up to
// BINDING_SIGNATURE_P256_DER_MAX_LEN decodes, not just a fixed-size one.
HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_BindingSignatureAttributesDecodeVariableLenSignature,
    TestSize.Level0)
{
    Attributes attributes = {};
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    AttachBindingSignatureAttributes(challenge_, std::vector<uint8_t>(1, 0x01), attributes);
    auto shortSign = DecodeBindingSignatureAttributes(attributes);
    EXPECT_TRUE(shortSign.has_value());
    EXPECT_EQ(shortSign->signature, std::vector<uint8_t>(1, 0x01));

    Attributes maxAttributes = {};
    maxAttributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    AttachBindingSignatureAttributes(challenge_, std::vector<uint8_t>(BINDING_SIGNATURE_P256_DER_MAX_LEN, 0xCD),
        maxAttributes);
    auto maxSign = DecodeBindingSignatureAttributes(maxAttributes);
    EXPECT_TRUE(maxSign.has_value());
    EXPECT_EQ(maxSign->signature.size(), BINDING_SIGNATURE_P256_DER_MAX_LEN);
}

// Unsigned (V1) message: the absent challenge/signature pair is reported as not carried
// and decode rejects it; consumers pass an empty proof and whether that is acceptable is
// judged inside the Rust module by the enrolled binding.
HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_BindingSignatureAttributesDecodeMissingProof,
    TestSize.Level0)
{
    Attributes attributes = {};
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    EXPECT_FALSE(HasBindingSignatureAttributes(attributes));
    auto emptyProof = DecodeBindingSignatureAttributes(attributes);
    EXPECT_FALSE(emptyProof.has_value());

    // partial pair: challenge without signature counts as carried and is rejected
    Attributes partialAttributes = {};
    partialAttributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    partialAttributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, challenge_);
    EXPECT_TRUE(HasBindingSignatureAttributes(partialAttributes));
    auto partialProof = DecodeBindingSignatureAttributes(partialAttributes);
    EXPECT_FALSE(partialProof.has_value());

    // an empty signature is rejected
    Attributes emptySignatureAttributes = {};
    emptySignatureAttributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    emptySignatureAttributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, challenge_);
    emptySignatureAttributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, std::vector<uint8_t> {});
    auto emptySignatureProof = DecodeBindingSignatureAttributes(emptySignatureAttributes);
    EXPECT_FALSE(emptySignatureProof.has_value());
}

// Challenge length is fixed at BINDING_SIGNATURE_CHALLENGE_LEN; mismatch is rejected here.
HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_BindingSignatureAttributesDecodeChallengeLenMismatch,
    TestSize.Level0)
{
    Attributes attributes = {};
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    AttachBindingSignatureAttributes(std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN / 2, 0x01), signature_,
        attributes);

    auto bindingSignatureOpt = DecodeBindingSignatureAttributes(attributes);
    EXPECT_FALSE(bindingSignatureOpt.has_value());
}

// Over-length signature input passes through untouched; the FFI boundary and the Rust module reject it.
HWTEST_F(BindingSignatureMessageTest, BindingSignatureMessageTest_BindingSignatureAttributesDecodeSignatureTooLong,
    TestSize.Level0)
{
    Attributes attributes = {};
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, challenge_);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE,
        std::vector<uint8_t>(BINDING_SIGNATURE_P256_DER_MAX_LEN + 1, 0x01));

    auto bindingSignatureOpt = DecodeBindingSignatureAttributes(attributes);
    EXPECT_TRUE(bindingSignatureOpt.has_value());
    EXPECT_EQ(bindingSignatureOpt->signature.size(), BINDING_SIGNATURE_P256_DER_MAX_LEN + 1);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
