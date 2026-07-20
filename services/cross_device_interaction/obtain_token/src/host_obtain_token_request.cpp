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
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "companion_manager.h"
#include "error_guard.h"
#include "misc_manager.h"
#include "request_stages.h"
#include "security_agent.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_OBTAIN_TOKEN_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostObtainTokenRequest::HostObtainTokenRequest(const std::string &connectionName, const Attributes &request,
    OnMessageReply &&replyCallback, const DeviceKey &companionDeviceKey)
    : InboundRequest(RequestType::HOST_OBTAIN_TOKEN_REQUEST, connectionName, companionDeviceKey),
      request_(request),
      preObtainTokenReplyCallback_(std::move(replyCallback))
{
    eventCollector_.SetConnectionName(connectionName);
    eventCollector_.SetCompanionDeviceKey(companionDeviceKey);
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

    if (!GetCompanionManager().IsCapabilitySupported(companionStatus->templateId, Capability::OBTAIN_TOKEN)) {
        IAM_LOGE("%{public}s OBTAIN_TOKEN capability not supported by companion device", GetDescription());
        return false;
    }

    if (!EnsureCompanionAuthMaintainActive(preRequest.companionDeviceKey, errorGuard)) {
        return false;
    }
    templateId_ = companionStatus->templateId;
    desc_.SetTemplateId(companionStatus->templateId);
    desc_.SetDeviceId(preRequest.companionDeviceKey);
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(preRequest.companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        IAM_LOGE("%{public}s failed to get secure protocol id", GetDescription());
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    eventCollector_.SetHostUserId(hostUserId_);
    eventCollector_.SetTemplateIdList({ companionStatus->templateId });
    return true;
}

bool HostObtainTokenRequest::OnStart(ErrorGuard &errorGuard)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    if (GetMiscManager().IsCompanionAuthBlocked()) {
        IAM_LOGE("%{public}s companion auth blocked", GetDescription());
        SendPreObtainTokenReply(ResultCode::LOCKED, {});
        return false;
    }
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
            [weakSelf = weak_from_this()](const Attributes &request, OnMessageReply &onMessageReply) {
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
    eventCollector_.EnterWait(HostObtainTokenStages::WAIT_OBTAIN_TOKEN);
    return true;
}

bool HostObtainTokenRequest::ProcessPreObtainToken(std::vector<uint8_t> &preObtainTokenReply)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    HostProcessPreObtainTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = *templateId_;
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
    ENSURE_OR_RETURN_DESC(GetDescription(), preObtainTokenReplyCallback_ != nullptr);
    Attributes reply = {};
    PreObtainTokenReply preReply = {};
    preReply.result = result;
    preReply.extraInfo = preObtainTokenReply;
    EncodePreObtainTokenReply(preReply, reply);

    preObtainTokenReplyCallback_(reply);
}

void HostObtainTokenRequest::HandleObtainTokenMessage(const Attributes &request, OnMessageReply &onMessageReply)
{
    eventCollector_.ExitWait(HostObtainTokenStages::DONE_OBTAIN_TOKEN);
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    ENSURE_OR_RETURN_DESC(GetDescription(), onMessageReply != nullptr);
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
        return;
    }

    ObtainTokenReply replyBody = {};
    replyBody.result = ResultCode::SUCCESS;
    replyBody.extraInfo = obtainTokenReply;
    Attributes reply = {};
    EncodeObtainTokenReply(replyBody, reply);

    onMessageReply(reply);
    errorGuard.Cancel();
    CompleteWithSuccess();
}

HostProcessObtainTokenInput HostObtainTokenRequest::BuildHostProcessObtainTokenInput(
    const std::vector<uint8_t> &obtainTokenRequest)
{
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), HostProcessObtainTokenInput {});
    HostProcessObtainTokenInput input = {};
    input.requestId = GetRequestId();
    input.templateId = *templateId_;
    input.secureProtocolId = secureProtocolId_;
    input.obtainTokenRequest = obtainTokenRequest;
    return input;
}

bool HostObtainTokenRequest::ProcessHostProcessObtainTokenOutput(const HostProcessObtainTokenOutput &output,
    std::vector<uint8_t> &obtainTokenReply)
{
    eventCollector_.SetAtl(output.atl);
    obtainTokenReply = output.obtainTokenReply;
    IAM_LOGI("%{public}s HostProcessObtainToken completed atl=%{public}d", GetDescription(), output.atl);

    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), templateId_.has_value(), false);
    bool setTokenAtlRet = GetCompanionManager().SetCompanionTokenAuthAtl(*templateId_, output.atl);
    if (!setTokenAtlRet) {
        IAM_LOGE("%{public}s SetCompanionTokenAuthAtl failed", GetDescription());
    }
    return setTokenAtlRet;
}

bool HostObtainTokenRequest::HandleHostProcessObtainToken(const ObtainTokenRequest &request,
    std::vector<uint8_t> &obtainTokenReply)
{
    HostProcessObtainTokenInput input = BuildHostProcessObtainTokenInput(request.extraInfo);

    HostProcessObtainTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostProcessObtainToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostProcessObtainToken failed ret=%{public}d", GetDescription(), ret);
        return false;
    }

    needCancelObtainToken_ = false;
    return ProcessHostProcessObtainTokenOutput(output, obtainTokenReply);
}

void HostObtainTokenRequest::CompleteWithError(ResultCode result)
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s: obtain token request failed, result=%{public}d", GetDescription(), result);
    if (needCancelObtainToken_) {
        HostCancelObtainTokenInput input = { GetRequestId() };
        ResultCode cancelRet = GetSecurityAgent().HostCancelObtainToken(input);
        if (cancelRet != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelObtainToken failed ret=%{public}d", GetDescription(), cancelRet);
        }
        needCancelObtainToken_ = false;
    }
    eventCollector_.Report(result);
    Destroy();
}

void HostObtainTokenRequest::CompleteWithSuccess()
{
    if (!AcquireCompletion()) {
        return;
    }
    IAM_LOGI("%{public}s complete with success", GetDescription());
    needCancelObtainToken_ = false;
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

std::weak_ptr<InboundRequest> HostObtainTokenRequest::GetWeakPtr()
{
    return weak_from_this();
}

uint32_t HostObtainTokenRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostObtainTokenRequest
}

bool HostObtainTokenRequest::ShouldCancelOnNewRequest(const IRequest &newRequest,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts HostObtainTokenRequest
    if (newRequest.GetRequestType() == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostObtainTokenRequest to same device preempts existing one
    if (newRequest.GetRequestType() == RequestType::HOST_OBTAIN_TOKEN_REQUEST &&
        GetPeerDeviceKey() == newRequest.GetPeerDeviceKey()) {
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
        return false;
    }
    if (!deviceStatus->isAuthMaintainActive) {
        IAM_LOGE("%{public}s device not in auth maintain active state", GetDescription());
        return false;
    }
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(deviceKey, false,
        [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandlePeerDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription());
        return false;
    }
    return true;
}

void HostObtainTokenRequest::HandlePeerDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    LogTraceGuard guard;
    const auto &peerDeviceKey = PeerDeviceKey();
    for (const auto &status : deviceStatusList) {
        if (status.deviceKey != peerDeviceKey) {
            continue;
        }
        if (!status.isAuthMaintainActive) {
            IAM_LOGE("%{public}s companion device left auth maintain state", GetDescription());
            // companion may already hold PreObtainTokenReply(SUCCESS) and be waiting for OBTAIN_TOKEN; a bare
            // CompleteWithError sends nothing to the companion (InboundRequest does not own the connection), so it
            // would hang until the 60s timeout. Cancel() emits REQUEST_ABORTED (the companion's OutboundRequest
            // subscribes to it during OpenConnection) so the companion can abort promptly. Symmetric to the
            // CompanionIssueTokenRequest::HandleAuthMaintainActiveChanged fix.
            Cancel(ResultCode::GENERAL_ERROR);
        }
        return;
    }
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
