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

#include "host_add_companion_request.h"

#include <chrono>

#include "iam_check.h"
#include "iam_logger.h"

#include "add_companion_message.h"
#include "common_defines.h"
#include "companion_manager.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "misc_manager.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostAddCompanionRequest::HostAddCompanionRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
    uint32_t tokenId, FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_ADD_COMPANION_REQUEST, scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(fwkMsg),
      tokenId_(tokenId),
      requestCallback_(std::move(requestCallback))
{
}

bool HostAddCompanionRequest::OnStart([[maybe_unused]] ErrorGuard &errorGuard)
{
    bool selectorSet = GetMiscManager().GetDeviceDeviceSelectResult(tokenId_, SelectPurpose::SELECT_ADD_DEVICE,
        [weakSelf = weak_from_this()](const std::vector<DeviceKey> &selectedDevices) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceSelectResult(selectedDevices);
        });
    ENSURE_OR_RETURN_VAL(selectorSet, false);
    return true;
}

void HostAddCompanionRequest::HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices)
{
    IAM_LOGI("%{public}s HandleDeviceSelectResult", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    if (selectedDevices.size() != 1) {
        IAM_LOGE("%{public}s unexpected number of devices selected: %{public}zu", GetDescription(),
            selectedDevices.size());
        return;
    }

    SetPeerDeviceKey(selectedDevices[0]);

    if (!OpenConnection()) {
        IAM_LOGE("%{public}s OpenConnection failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

void HostAddCompanionRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto hostDeviceKeyOpt = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    ENSURE_OR_RETURN(hostDeviceKeyOpt.has_value());
    hostDeviceKey_ = *hostDeviceKeyOpt;

    auto secureProtocolIdOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(*GetPeerDeviceKey());
    ENSURE_OR_RETURN(secureProtocolIdOpt.has_value());
    secureProtocolId_ = *secureProtocolIdOpt;

    HostGetInitKeyNegotiationRequestInput input = {
        .requestId = GetRequestId(),
        .secureProtocolId = secureProtocolId_,
    };
    HostGetInitKeyNegotiationRequestOutput output = {};
    ResultCode ret = GetSecurityAgent().HostGetInitKeyNegotiationRequest(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostGetInitKeyNegotiationRequest failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    needCancelCompanionAdd_ = true;

    InitKeyNegotiationRequest initRequest { .hostDeviceKey = hostDeviceKey_,
        .extraInfo = output.initKeyNegotiationRequest };
    Attributes request = {};
    bool encodeRet = EncodeInitKeyNegotiationRequest(initRequest, request);
    ENSURE_OR_RETURN(encodeRet);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::INIT_KEY_NEGOTIATION,
        request, [weakSelf = weak_from_this()](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleInitKeyNegotiationReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

std::weak_ptr<OutboundRequest> HostAddCompanionRequest::GetWeakPtr()
{
    return shared_from_this();
}

void HostAddCompanionRequest::HandleInitKeyNegotiationReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto initReplyOpt = DecodeInitKeyNegotiationReply(reply);
    ENSURE_OR_RETURN(initReplyOpt.has_value());

    const auto &initReply = *initReplyOpt;
    if (initReply.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s init key negotiation failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(initReply.result));
        errorGuard.UpdateErrorCode(initReply.result);
        return;
    }

    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN(companionDeviceKey.has_value());

    std::vector<uint8_t> addHostBindingRequest;
    bool ret = BeginAddCompanion(initReply, addHostBindingRequest, errorGuard);
    ENSURE_OR_RETURN(ret);

    BeginAddHostBindingRequest beginRequest = { .companionUserId = companionDeviceKey->deviceUserId,
        .extraInfo = addHostBindingRequest };
    Attributes request = {};
    bool encodeRet = EncodeBeginAddHostBindingRequest(beginRequest, request);
    ENSURE_OR_RETURN(encodeRet);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::BEGIN_ADD_HOST_BINDING,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleBeginAddHostBindingReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool HostAddCompanionRequest::BeginAddCompanion(const InitKeyNegotiationReply &reply,
    std::vector<uint8_t> &addHostBindingRequest, ErrorGuard &errorGuard)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), false);

    BeginAddCompanionParams params = {};
    params.requestId = GetRequestId();
    params.scheduleId = GetScheduleId();
    params.hostDeviceKey = hostDeviceKey_;
    params.companionDeviceKey = *companionDeviceKey;
    params.fwkMsg = fwkMsg_;
    params.secureProtocolId = secureProtocolId_;
    params.initKeyNegotiationReply = reply.extraInfo;
    ResultCode ret = GetCompanionManager().BeginAddCompanion(params, addHostBindingRequest);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginAddCompanion failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return false;
    }
    return true;
}

void HostAddCompanionRequest::HandleBeginAddHostBindingReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    auto beginReplyOpt = DecodeBeginAddHostBindingReply(reply);
    ENSURE_OR_RETURN(beginReplyOpt.has_value());

    if (beginReplyOpt->result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s companion check failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(beginReplyOpt->result));
        errorGuard.UpdateErrorCode(beginReplyOpt->result);
        return;
    }

    bool handleRet = EndAddCompanion(*beginReplyOpt, addCompanionFwkMsg_);
    ENSURE_OR_RETURN(handleRet);

    bool sendRet = SendEndAddHostBindingMsg(ResultCode::SUCCESS);
    if (!sendRet) {
        // send end add host binding msg fail does not affect the result of the request
        IAM_LOGE("%{public}s SendEndAddHostBindingMsg failed", GetDescription());
    }

    errorGuard.Cancel();
}

bool HostAddCompanionRequest::EndAddCompanion(const BeginAddHostBindingReply &reply, std::vector<uint8_t> &fwkMsg)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), false);

    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(*companionDeviceKey);
    ENSURE_OR_RETURN_VAL(deviceStatus.has_value(), false);

    PersistedCompanionStatus companionStatus = {};
    companionStatus.hostUserId = hostDeviceKey_.deviceUserId;
    companionStatus.companionDeviceKey = *companionDeviceKey;
    companionStatus.secureProtocolId = deviceStatus->secureProtocolId;
    companionStatus.deviceModelInfo = deviceStatus->deviceModelInfo;
    companionStatus.deviceUserName = deviceStatus->deviceUserName;
    companionStatus.deviceName = deviceStatus->deviceName;
    companionStatus.isValid = true;

    std::vector<uint8_t> tokenData;
    Atl atl = 0;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = GetRequestId();
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = secureProtocolId_;
    inputParam.addHostBindingReply = reply.extraInfo;
    ResultCode ret = GetCompanionManager().EndAddCompanion(inputParam, fwkMsg, tokenData, atl);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s EndAddCompanion failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    needCancelCompanionAdd_ = false;
    needCancelIssueToken_ = true;

    auto companionStatusOpt =
        GetCompanionManager().GetCompanionStatus(companionStatus.hostUserId, companionStatus.companionDeviceKey);
    ENSURE_OR_RETURN_VAL(companionStatusOpt.has_value(), false);
    templateId_ = companionStatusOpt->templateId;

    pendingTokenData_ = std::move(tokenData);
    tokenAtl_ = atl;
    return true;
}

bool HostAddCompanionRequest::SendEndAddHostBindingMsg(ResultCode result)
{
    auto companionDeviceKey = GetPeerDeviceKey();
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), false);

    EndAddHostBindingRequest requestMsg = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionDeviceKey->deviceUserId,
        .result = result,
        .extraInfo = pendingTokenData_ }; // 包含加密后的 Token 数据（仅当成功时非空）
    Attributes request = {};
    bool encodeRet = EncodeEndAddHostBindingRequest(requestMsg, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::END_ADD_HOST_BINDING,
        request, [weakSelf = weak_from_this()](const Attributes &message) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleEndAddHostBindingReply(message);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostAddCompanionRequest::HandleEndAddHostBindingReply(const Attributes &reply)
{
    ErrorGuard errorGuard([this](ResultCode result) { CompleteWithError(result); });

    IAM_LOGI("%{public}s", GetDescription());
    auto replyMsgOpt = DecodeEndAddHostBindingReply(reply);
    ENSURE_OR_RETURN(replyMsgOpt.has_value());

    const auto &replyMsg = *replyMsgOpt;

    if (replyMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s token distribution failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyMsg.result));
        errorGuard.UpdateErrorCode(replyMsg.result);
        return;
    }

    ENSURE_OR_RETURN(templateId_ != 0);
    ResultCode ret = GetCompanionManager().ActivateToken(GetRequestId(), templateId_, tokenAtl_);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s ActivateToken failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needCancelIssueToken_ = false;
    IAM_LOGI("%{public}s token activated successfully", GetDescription());

    errorGuard.Cancel();
    CompleteWithSuccess();
}

void HostAddCompanionRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    if (callbackInvoked_) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }

    ENSURE_OR_RETURN(requestCallback_ != nullptr);
    callbackInvoked_ = true;
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, extra = extraInfo]() mutable {
            if (cb) {
                cb(result, extra);
            }
        });
}

void HostAddCompanionRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    if (needCancelCompanionAdd_) {
        HostCancelAddCompanionInput input { GetRequestId() };
        ResultCode ret = GetSecurityAgent().HostCancelAddCompanion(input);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelAddCompanion failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelCompanionAdd_ = false;
    }
    if (needCancelIssueToken_) {
        HostCancelIssueTokenInput cancelInput = { .requestId = GetRequestId() };
        ResultCode ret = GetSecurityAgent().HostCancelIssueToken(cancelInput);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s HostCancelIssueToken failed ret=%{public}d", GetDescription(), ret);
        }
        needCancelIssueToken_ = false;
    }
    InvokeCallback(result, {});
    Destroy();
}

void HostAddCompanionRequest::CompleteWithSuccess()
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, addCompanionFwkMsg_);
    needCancelCompanionAdd_ = false;
    Destroy();
}

uint32_t HostAddCompanionRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostAddCompanionRequest
}

bool HostAddCompanionRequest::ShouldCancelOnNewRequest([[maybe_unused]] RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostAddCompanionRequest preempts existing one
    if (newRequestType == RequestType::HOST_ADD_COMPANION_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostAddCompanion", GetDescription());
        return true;
    }

    // Spec: new HostDelegateAuthRequest preempts HostAddCompanionRequest
    if (newRequestType == RequestType::HOST_DELEGATE_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostDelegateAuth", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
