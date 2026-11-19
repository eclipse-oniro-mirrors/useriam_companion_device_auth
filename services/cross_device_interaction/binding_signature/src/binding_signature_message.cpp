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

#include "iam_check.h"
#include "iam_logger.h"

#include "common_message.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_BINDING_SIGNATURE_MESSAGE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void EncodeGetBindingSignatureChallengeRequest(const GetBindingSignatureChallengeRequest &request,
    Attributes &attributes)
{
    EncodeHostDeviceKey(request.hostDeviceKey, attributes);
    if (request.companionUserKey.has_value()) {
        EncodeCompanionUserKey(*request.companionUserKey, attributes);
    }
}

std::optional<GetBindingSignatureChallengeRequest> DecodeGetBindingSignatureChallengeRequest(
    const Attributes &attributes)
{
    GetBindingSignatureChallengeRequest request = {};
    bool getConnectionNameRet =
        attributes.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, request.connectionName);
    ENSURE_OR_RETURN_VAL(getConnectionNameRet, std::nullopt);
    auto hostKeyOpt = DecodeHostDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(hostKeyOpt.has_value(), std::nullopt);
    request.hostDeviceKey = *hostKeyOpt;

    if (HasCompanionUserKey(attributes)) {
        auto companionUserKey = DecodeCompanionUserKey(attributes);
        ENSURE_OR_RETURN_VAL(companionUserKey.has_value(), std::nullopt);
        request.companionUserKey = *companionUserKey;
    }
    return request;
}

void EncodeGetBindingSignatureChallengeReply(const GetBindingSignatureChallengeReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    if (reply.result != ResultCode::SUCCESS) {
        return;
    }
    EncodeCompanionUserKey(reply.companionUserKey, attributes);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, reply.challenge);
}

std::optional<GetBindingSignatureChallengeReply> DecodeGetBindingSignatureChallengeReply(const Attributes &attributes)
{
    GetBindingSignatureChallengeReply reply = {};
    int32_t result = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);
    reply.result = static_cast<ResultCode>(result);
    if (reply.result != ResultCode::SUCCESS) {
        return reply;
    }
    ENSURE_OR_RETURN_VAL(HasCompanionUserKey(attributes), std::nullopt);
    auto companionUserKey = DecodeCompanionUserKey(attributes);
    ENSURE_OR_RETURN_VAL(companionUserKey.has_value(), std::nullopt);
    reply.companionUserKey = *companionUserKey;
    bool getChallengeRet =
        attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, reply.challenge);
    ENSURE_OR_RETURN_VAL(getChallengeRet, std::nullopt);
    ENSURE_OR_RETURN_VAL(reply.challenge.size() == BINDING_SIGNATURE_CHALLENGE_LEN, std::nullopt);
    return reply;
}

bool HasBindingSignatureAttributes(const Attributes &attributes)
{
    bool hasChallenge = attributes.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE);
    bool hasSignature = attributes.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE);
    return hasChallenge || hasSignature;
}

std::optional<BindingSignatureProof> DecodeBindingSignatureAttributes(const Attributes &attributes)
{
    BindingSignatureProof bindingSignature = {};

    bool getChallengeRet =
        attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, bindingSignature.challenge);
    ENSURE_OR_RETURN_VAL(getChallengeRet, std::nullopt);
    ENSURE_OR_RETURN_VAL(bindingSignature.challenge.size() == BINDING_SIGNATURE_CHALLENGE_LEN, std::nullopt);
    bool getSignatureRet =
        attributes.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, bindingSignature.signature);
    ENSURE_OR_RETURN_VAL(getSignatureRet, std::nullopt);
    ENSURE_OR_RETURN_VAL(!bindingSignature.signature.empty(), std::nullopt);
    return bindingSignature;
}

void AttachBindingSignatureAttributes(const std::vector<uint8_t> &challenge, const std::vector<uint8_t> &signature,
    Attributes &attributes)
{
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, challenge);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, signature);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
