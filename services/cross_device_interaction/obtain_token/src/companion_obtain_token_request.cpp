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

#include "companion_obtain_token_request.h"

#include <optional>

#include "iam_check.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "host_binding_manager.h"
#include "obtain_token_message.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionObtainTokenRequest::CompanionObtainTokenRequest(const DeviceKey &hostDeviceKey,
    const std::vector<uint8_t> &fwkUnlockMsg)
    : OutboundRequest(RequestType::COMPANION_OBTAIN_TOKEN_REQUEST, 0, DEFAULT_REQUEST_TIMEOUT_MS),
      hostDeviceKey_(hostDeviceKey),
      fwkUnlockMsg_(fwkUnlockMsg)
{
}

bool CompanionObtainTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    if (!GetCrossDeviceCommManager().IsAuthMaintainActive()) {
        IAM_LOGE("%{public}s local auth maintain inactive", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    localDeviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeIsAuthMaintainActive(
        [weakSelf = std::weak_ptr<CompanionObtainTokenRequest>(shared_from_this())](bool isActive) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleAuthMaintainActiveChanged(isActive);
        });
    if (localDeviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe auth maintain active", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }

    SetPeerDeviceKey(hostDeviceKey_);

    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }

    return true;
}

void CompanionObtainTokenRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto localDeviceKeyOpt = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN(localDeviceKeyOpt.has_value());
    companionDeviceKey_ = localDeviceKeyOpt.value();
    secureProtocolId_ = GetCrossDeviceCommManager().CompanionGetSecureProtocolId();

    bool ret = SendPreObtainTokenRequest();
    if (!ret) {
        IAM_LOGE("%{public}s SendPreObtainTokenRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool CompanionObtainTokenRequest::SendPreObtainTokenRequest()
{
    Attributes request = {};
    PreObtainTokenRequest preObtainTokenRequest = {
        .hostUserId = hostDeviceKey_.deviceUserId,
        .companionDeviceKey = companionDeviceKey_,
        .extraInfo = {},
    };
    bool encodeRet = EncodePreObtainTokenRequest(preObtainTokenRequest, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<CompanionObtainTokenRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::PRE_OBTAIN_TOKEN, request,
        [weakSelf](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePreObtainTokenReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void CompanionObtainTokenRequest::HandlePreObtainTokenReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    PreObtainTokenReply preObtainTokenReply = {};
    bool decodeRet = DecodePreObtainTokenReply(reply, preObtainTokenReply);
    ENSURE_OR_RETURN(decodeRet);

    ResultCode result = static_cast<ResultCode>(preObtainTokenReply.result);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s get result=%{public}d", GetDescription(), preObtainTokenReply.result);
        errorGuard.UpdateErrorCode(result);
        return;
    }

    bool beginRet = CompanionBeginObtainToken(preObtainTokenReply);
    if (!beginRet) {
        IAM_LOGE("%{public}s CompanionBeginObtainToken failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool CompanionObtainTokenRequest::CompanionBeginObtainToken(const PreObtainTokenReply &preObtainTokenReply)
{
    requestId_ = static_cast<int32_t>(preObtainTokenReply.requestId);
    auto hostBindingStatus =
        GetHostBindingManager().GetHostBindingStatus(companionDeviceKey_.deviceUserId, hostDeviceKey_);
    if (!hostBindingStatus.has_value()) {
        IAM_LOGE("%{public}s GetHostBindingStatus failed", GetDescription());
        return false;
    }
    bindingId_ = hostBindingStatus->bindingId;

    CompanionBeginObtainTokenInput input = {};
    input.requestId = requestId_;
    input.bindingId = bindingId_;
    input.fwkUnlockMsg = fwkUnlockMsg_;
    input.secureProtocolId = secureProtocolId_;
    input.preObtainTokenReply = preObtainTokenReply.extraInfo;

    CompanionBeginObtainTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().CompanionBeginObtainToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionBeginObtainToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    needCancelObtainToken_ = true;
    return SendObtainTokenRequest(preObtainTokenReply.requestId, output.obtainTokenRequest);
}

bool CompanionObtainTokenRequest::SendObtainTokenRequest(RequestId requestId,
    const std::vector<uint8_t> &obtainTokenRequest)
{
    Attributes request = {};
    ObtainTokenRequest obtainRequest = {
        .hostUserId = hostDeviceKey_.deviceUserId,
        .requestId = requestId,
        .extraInfo = obtainTokenRequest,
        .companionDeviceKey = companionDeviceKey_,
    };
    bool encodeRet = EncodeObtainTokenRequest(obtainRequest, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<CompanionObtainTokenRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::OBTAIN_TOKEN, request,
        [weakSelf, requestId](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleObtainTokenReply(reply, requestId);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void CompanionObtainTokenRequest::HandleObtainTokenReply(const Attributes &reply, RequestId requestId)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    ObtainTokenReply obtainTokenReply = {};
    bool decodeRet = DecodeObtainTokenReply(reply, obtainTokenReply);
    ENSURE_OR_RETURN(decodeRet);

    ResultCode result = static_cast<ResultCode>(obtainTokenReply.result);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s get result=%{public}d", GetDescription(), obtainTokenReply.result);
        errorGuard.UpdateErrorCode(result);
        return;
    }

    bool endRet = CompanionEndObtainToken(obtainTokenReply, requestId);
    if (!endRet) {
        IAM_LOGE("%{public}s CompanionEndObtainToken failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return;
    }
    needCancelObtainToken_ = false;
    errorGuard.Cancel();
    CompleteWithSuccess();
}

bool CompanionObtainTokenRequest::CompanionEndObtainToken(const ObtainTokenReply &obtainTokenReply, RequestId requestId)
{
    CompanionEndObtainTokenInput input = {};
    input.requestId = requestId;
    input.secureProtocolId = secureProtocolId_;
    input.obtainTokenReply = obtainTokenReply.extraInfo;
    ResultCode ret = GetSecurityAgent().CompanionEndObtainToken(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s CompanionEndObtainToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    bool setTokenValidRet = GetHostBindingManager().SetHostBindingTokenValid(bindingId_, true);
    if (!setTokenValidRet) {
        IAM_LOGE("%{public}s SetHostBindingTokenValid failed", GetDescription());
    }
    return true;
}

void CompanionObtainTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    localDeviceStatusSubscription_.reset();
    if (needCancelObtainToken_) {
        CompanionCancelObtainTokenInput input = { requestId_ };
        ResultCode cancelRet = GetSecurityAgent().CompanionCancelObtainToken(input);
        if (cancelRet != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s CompanionCancelObtainToken failed ret=%{public}d", GetDescription(), cancelRet);
        }
        needCancelObtainToken_ = false;
    }
    Destroy();
}

void CompanionObtainTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    localDeviceStatusSubscription_.reset();
    Destroy();
}

uint32_t CompanionObtainTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent CompanionObtainTokenRequest
}

bool CompanionObtainTokenRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new CompanionObtainTokenRequest to same device preempts existing one
    if (newRequestType == RequestType::COMPANION_OBTAIN_TOKEN_REQUEST && GetPeerDeviceKey() == newPeerDevice) {
        IAM_LOGI("%{public}s: preempted by new CompanionObtainToken to same device", GetDescription());
        return true;
    }

    return false;
}

std::weak_ptr<OutboundRequest> CompanionObtainTokenRequest::GetWeakPtr()
{
    return shared_from_this();
}

void CompanionObtainTokenRequest::HandleAuthMaintainActiveChanged(bool isActive)
{
    if (isActive) {
        return;
    }
    IAM_LOGE("%{public}s local auth maintain inactive, cancel request", GetDescription());
    CompleteWithError(ResultCode::GENERAL_ERROR);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
