/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "companion_add_companion_request.h"

#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "add_companion_message.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionAddCompanionRequest::CompanionAddCompanionRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply &&replyCallback, const DeviceKey &hostDeviceKey)
    : InboundRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, connectionName, hostDeviceKey),
      initKeyNegoRequest_(request),
      currentReply_(std::move(replyCallback))
{
}

bool CompanionAddCompanionRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s start", GetDescription());

    auto companionKeyOpt = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), companionKeyOpt.has_value(), false);
    companionDeviceKey_ = *companionKeyOpt;

    secureProtocolId_ = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), secureProtocolId_ != SecureProtocolId::INVALID, false);

    beginAddHostBindingSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::BEGIN_ADD_HOST_BINDING,
            [weakSelf = weak_from_this()](const Attributes &msg, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
                self->HandleBeginAddCompanion(msg, onMessageReply);
            });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), beginAddHostBindingSubscription_ != nullptr, false);

    endAddHostBindingSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::END_ADD_HOST_BINDING,
            [weakSelf = weak_from_this()](const Attributes &msg, OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
                self->HandleEndAddCompanion(msg, onMessageReply);
            });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), endAddHostBindingSubscription_ != nullptr, false);

    auto initRequestOpt = DecodeInitKeyNegotiationRequest(initKeyNegoRequest_);
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), initRequestOpt.has_value(), false);
    if (initRequestOpt->hostDeviceKey != PeerDeviceKey()) {
        IAM_LOGE("%{public}s host device key mismatch", GetDescription());
        return false;
    }

    std::vector<uint8_t> initKeyNegotiationReply;
    bool initRet = CompanionInitKeyNegotiation(*initRequestOpt, initKeyNegotiationReply);
    if (!initRet) {
        IAM_LOGE("%{public}s CompanionInitKeyNegotiation failed", GetDescription());
        return false;
    }

    bool ret = SendInitKeyNegotiationReply(ResultCode::SUCCESS, initKeyNegotiationReply);
    if (!ret) {
        IAM_LOGE("%{public}s SendInitKeyNegotiationReply failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }

    errorGuard.Cancel();
    return true;
}

bool CompanionAddCompanionRequest::CompanionInitKeyNegotiation(const InitKeyNegotiationRequest &request,
    std::vector<uint8_t> &initKeyNegotiationReply)
{
    IAM_LOGI("%{public}s start", GetDescription());

    CompanionInitKeyNegotiationInput input = {};
    input.requestId = GetRequestId();
    input.secureProtocolId = secureProtocolId_;
    input.companionDeviceKey = companionDeviceKey_;
    input.hostDeviceKey = PeerDeviceKey();
    input.initKeyNegotiationRequest = request.extraInfo;

    CompanionInitKeyNegotiationOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionInitKeyNegotiation(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionInitKeyNegotiation failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    needCancelAddCompanion_ = true;

    initKeyNegotiationReply = output.initKeyNegotiationReply;
    return true;
}

bool CompanionAddCompanionRequest::SendInitKeyNegotiationReply(ResultCode result,
    const std::vector<uint8_t> &initKeyNegotiationReply)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), currentReply_ != nullptr, false);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = result, .extraInfo = initKeyNegotiationReply };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;
    return true;
}

void CompanionAddCompanionRequest::HandleBeginAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);

    currentReply_ = std::move(onMessageReply);
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto requestOpt = DecodeBeginAddHostBindingRequest(attrInput);
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt.has_value());

    std::vector<uint8_t> addHostBindingReply;
    ResultCode ret = GetHostBindingManager().BeginAddHostBinding(GetRequestId(), requestOpt->companionUserId,
        secureProtocolId_, requestOpt->extraInfo, addHostBindingReply);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionBeginAddHostBinding failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = addHostBindingReply };
    Attributes reply;
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;

    errorGuard.Cancel();
}

void CompanionAddCompanionRequest::HandleEndAddCompanion(const Attributes &attrInput, OnMessageReply &onMessageReply)
{
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);

    currentReply_ = std::move(onMessageReply);
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto requestOpt = DecodeEndAddHostBindingRequest(attrInput);
    ENSURE_OR_RETURN_DESC(GetDescription(), requestOpt.has_value());

    IAM_LOGI("%{public}s Get resultCode %{public}d hostUserId %{public}d companionUserId %{public}d", GetDescription(),
        requestOpt->result, requestOpt->hostDeviceKey.deviceUserId, requestOpt->companionUserId);

    // Extract Token data if binding was successful
    std::vector<uint8_t> tokenData;
    if (requestOpt->result == ResultCode::SUCCESS && !requestOpt->extraInfo.empty()) {
        tokenData = requestOpt->extraInfo;
        IAM_LOGI("%{public}s receive token data from host, size=%{public}zu", GetDescription(), tokenData.size());
    }

    ResultCode ret = GetHostBindingManager().EndAddHostBinding(GetRequestId(), requestOpt->result, tokenData);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionEndAddHostBinding failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needCancelAddCompanion_ = false;

    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    Attributes reply;
    EncodeEndAddHostBindingReply(replyMsg, reply);

    currentReply_(reply);
    currentReply_ = nullptr;

    errorGuard.Cancel();
    CompleteWithSuccess();
}

std::weak_ptr<InboundRequest> CompanionAddCompanionRequest::GetWeakPtr()
{
    return shared_from_this();
}

void CompanionAddCompanionRequest::SendErrorReply(ResultCode result)
{
    if (currentReply_ == nullptr) {
        IAM_LOGE("%{public}s reply already sent", GetDescription());
        return;
    }

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);

    currentReply_(reply);
    currentReply_ = nullptr;
}

void CompanionAddCompanionRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    SendErrorReply(result);
    if (needCancelAddCompanion_) {
        ResultCode ret = GetHostBindingManager().EndAddHostBinding(GetRequestId(), result);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s EndAddHostBinding cancel failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelAddCompanion_ = false;
    }
    Destroy();
}

void CompanionAddCompanionRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Destroy();
}

uint32_t CompanionAddCompanionRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent CompanionAddCompanionRequest
}

bool CompanionAddCompanionRequest::ShouldCancelOnNewRequest([[maybe_unused]] RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionAddCompanionRequest preempts existing one
    if (newRequestType == RequestType::COMPANION_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new CompanionAddCompanion", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
