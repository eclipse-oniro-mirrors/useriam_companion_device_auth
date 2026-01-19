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

#include "host_obtain_token_request.h"

#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostObtainTokenRequest::HostObtainTokenRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply replyCallback, const DeviceKey &companionDeviceKey)
    : InboundRequest(RequestType::HOST_OBTAIN_TOKEN_REQUEST, connectionName, companionDeviceKey),
      request_(request),
      preObtainTokenReplyCallback_(std::move(replyCallback))
{
}

bool HostObtainTokenRequest::ParsePreObtainTokenRequest(ErrorGuard &errorGuard)
{
    auto preRequestOpt = DecodePreObtainTokenRequest(request_);
    if (!preRequestOpt.has_value()) {
        IAM_LOGE("%{public}s DecodePreObtainTokenRequest failed", GetDescription());
        return false;
    }
    const auto &preRequest = *preRequestOpt;

    hostUserId_ = preRequest.hostUserId;
    companionUserId_ = preRequest.companionDeviceKey.deviceUserId;
    if (preRequest.companionDeviceKey != PeerDeviceKey()) {
        IAM_LOGE("%{public}s companion device key mismatch", GetDescription());
        return false;
    }

    auto companionStatus = GetCompanionManager().GetCompanionStatus(hostUserId_, preRequest.companionDeviceKey);
    if (!companionStatus.has_value()) {
        IAM_LOGE("%{public}s companion status not found", GetDescription());
        return false;
    }
    if (!EnsureCompanionAuthMaintainActive(preRequest.companionDeviceKey, errorGuard)) {
        return false;
    }
    templateId_ = companionStatus->templateId;
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(preRequest.companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        IAM_LOGE("%{public}s failed to get secure protocol id", GetDescription());
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    return true;
}

bool HostObtainTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s", GetDescription());
    if (!ParsePreObtainTokenRequest(errorGuard)) {
        IAM_LOGE("%{public}s ParsePreObtainTokenRequest failed", GetDescription());
        SendPreObtainTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }

    std::vector<uint8_t> preObtainTokenReply;
    bool ret = ProcessPreObtainToken(preObtainTokenReply);
    if (!ret) {
        IAM_LOGE("%{public}s HostProcessPreObtainToken failed", GetDescription());
        SendPreObtainTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }

    obtainTokenSubscription_ =
        GetCrossDeviceCommManager().SubscribeMessage(GetConnectionName(), MessageType::OBTAIN_TOKEN,
            [weakSelf = std::weak_ptr<HostObtainTokenRequest>(shared_from_this())](const Attributes &request,
                OnMessageReply &onMessageReply) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleObtainTokenMessage(request, onMessageReply);
            });
    if (obtainTokenSubscription_ == nullptr) {
        IAM_LOGE("%{public}s subscribe obtain token failed", GetDescription());
        SendPreObtainTokenReply(ResultCode::GENERAL_ERROR, {});
        return false;
    }

    SendPreObtainTokenReply(ResultCode::SUCCESS, preObtainTokenReply);
    errorGuard.Cancel();
    return true;
}

bool HostObtainTokenRequest::ProcessPreObtainToken(std::vector<uint8_t> &preObtainTokenReply)
{
    HostProcessPreObtainTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = templateId_;
    input.secureProtocolId = secureProtocolId_;

    HostProcessPreObtainTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostProcessPreObtainToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostProcessPreObtainToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    preObtainTokenReply = output.preObtainTokenReply;
    needCancelObtainToken_ = true;
    return true;
}

void HostObtainTokenRequest::SendPreObtainTokenReply(ResultCode result, const std::vector<uint8_t> &preObtainTokenReply)
{
    ENSURE_OR_RETURN(preObtainTokenReplyCallback_ != nullptr);
    Attributes reply = {};
    PreObtainTokenReply preReply = {};
    preReply.result = result;
    preReply.extraInfo = preObtainTokenReply;
    bool encodeRet = EncodePreObtainTokenReply(preReply, reply);
    ENSURE_OR_RETURN(encodeRet);

    preObtainTokenReplyCallback_(reply);
}

void HostObtainTokenRequest::HandleObtainTokenMessage(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ENSURE_OR_RETURN(onMessageReply != nullptr);
    ErrorGuard errorGuard([this, &onMessageReply](ResultCode code) {
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(code));
        onMessageReply(reply);
        CompleteWithError(code);
    });

    auto obtainTokenRequestOpt = DecodeObtainTokenRequest(request);
    if (!obtainTokenRequestOpt.has_value()) {
        IAM_LOGE("%{public}s DecodeObtainTokenRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
        return;
    }
    const auto &obtainTokenRequest = *obtainTokenRequestOpt;

    if (obtainTokenRequest.hostUserId != hostUserId_ ||
        obtainTokenRequest.companionDeviceKey.deviceUserId != companionUserId_) {
        IAM_LOGE("%{public}s user id mismatch", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
        return;
    }
    const auto &peerKey = PeerDeviceKey();
    const auto &companionKey = obtainTokenRequest.companionDeviceKey;
    if (peerKey.deviceUserId != companionKey.deviceUserId || peerKey.idType != companionKey.idType ||
        peerKey.deviceId != companionKey.deviceId) {
        IAM_LOGE("%{public}s device key mismatch", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
        return;
    }

    std::vector<uint8_t> obtainTokenReply = {};
    bool ret = HandleHostProcessObtainToken(obtainTokenRequest, obtainTokenReply);
    if (!ret) {
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return;
    }

    ObtainTokenReply replyBody = {};
    replyBody.result = ResultCode::SUCCESS;
    replyBody.extraInfo = obtainTokenReply;
    Attributes reply = {};
    bool encodeReplyRet = EncodeObtainTokenReply(replyBody, reply);
    ENSURE_OR_RETURN(encodeReplyRet);

    onMessageReply(reply);
    errorGuard.Cancel();
    CompleteWithSuccess();
}

bool HostObtainTokenRequest::HandleHostProcessObtainToken(const ObtainTokenRequest &request,
    std::vector<uint8_t> &obtainTokenReply)
{
    HostProcessObtainTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = templateId_;
    input.secureProtocolId = secureProtocolId_;
    input.obtainTokenRequest = request.extraInfo;

    HostProcessObtainTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostProcessObtainToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostProcessObtainToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    obtainTokenReply = output.obtainTokenReply;
    IAM_LOGI("%{public}s HostProcessObtainToken success atl=%{public}d", GetDescription(), output.atl);

    bool setTokenAtlRet = GetCompanionManager().SetCompanionTokenAtl(templateId_, output.atl);
    if (!setTokenAtlRet) {
        IAM_LOGE("%{public}s SetCompanionTokenAtl failed", GetDescription());
    }
    needCancelObtainToken_ = false;
    return setTokenAtlRet;
}

void HostObtainTokenRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: obtain token request failed, result=%{public}d", GetDescription(), result);
    if (needCancelObtainToken_) {
        HostCancelObtainTokenInput input = { GetRequestId() };
        ResultCode cancelRet = GetSecurityAgent().HostCancelObtainToken(input);
        if (cancelRet != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelObtainToken failed ret=%{public}d", GetDescription(), cancelRet);
        }
        needCancelObtainToken_ = false;
    }
    Destroy();
}

void HostObtainTokenRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    needCancelObtainToken_ = false;
    Destroy();
}

std::weak_ptr<InboundRequest> HostObtainTokenRequest::GetWeakPtr()
{
    return shared_from_this();
}

uint32_t HostObtainTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostObtainTokenRequest
}

bool HostObtainTokenRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostObtainTokenRequest
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostObtainTokenRequest to same device preempts existing one
    if (newRequestType == RequestType::HOST_OBTAIN_TOKEN_REQUEST && GetPeerDeviceKey() == newPeerDevice) {
        IAM_LOGI("%{public}s: preempted by new HostObtainToken to same device", GetDescription());
        return true;
    }

    return false;
}

bool HostObtainTokenRequest::EnsureCompanionAuthMaintainActive(const DeviceKey &deviceKey, ErrorGuard &errorGuard)
{
    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(deviceKey);
    if (!deviceStatus.has_value()) {
        IAM_LOGE("%{public}s failed to get device status", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    if (!deviceStatus->isAuthMaintainActive) {
        IAM_LOGE("%{public}s device not in auth maintain active state", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(deviceKey,
        [weakSelf = std::weak_ptr<HostObtainTokenRequest>(shared_from_this())](
            const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePeerDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    return true;
}

void HostObtainTokenRequest::HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    const auto &peerDeviceKey = PeerDeviceKey();
    for (const auto &status : deviceStatusList) {
        if (status.deviceKey != peerDeviceKey) {
            continue;
        }
        if (!status.isAuthMaintainActive) {
            IAM_LOGE("%{public}s companion device left auth maintain state", GetDescription());
            CompleteWithError(ResultCode::GENERAL_ERROR);
        }
        return;
    }
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
