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

#include "host_token_auth_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "companion_token_auth_handler.h"
#include "cross_device_comm_manager_impl.h"
#include "error_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostTokenAuthRequest::HostTokenAuthRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, UserId hostUserId,
    TemplateId templateId, FwkResultCallback &&requestCallback)
    : OutboundRequest(RequestType::HOST_TOKEN_AUTH_REQUEST, scheduleId, DEFAULT_REQUEST_TIMEOUT_MS),
      fwkMsg_(fwkMsg),
      hostUserId_(hostUserId),
      templateId_(templateId),
      requestCallback_(std::move(requestCallback))
{
}

HostTokenAuthRequest::~HostTokenAuthRequest()
{
}

bool HostTokenAuthRequest::OnStart(ErrorGuard &errorGuard)
{
    IAM_LOGI("%{public}s", GetDescription());
    auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId_);
    if (!companionStatus.has_value()) {
        return false;
    }
    const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
    SetPeerDeviceKey(companionDeviceKey);
    companionUserId_ = companionStatus->companionDeviceStatus.deviceKey.deviceUserId;
    auto secureProtocolOpt = GetCrossDeviceCommManager().HostGetSecureProtocolId(companionDeviceKey);
    if (!secureProtocolOpt.has_value()) {
        errorGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return false;
    }
    secureProtocolId_ = secureProtocolOpt.value();
    if (!OpenConnection()) {
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return false;
    }
    return true;
}

void HostTokenAuthRequest::OnConnected()
{
    IAM_LOGI("%{public}s", GetDescription());
    HostBeginTokenAuth();
}

std::weak_ptr<OutboundRequest> HostTokenAuthRequest::GetWeakPtr()
{
    return shared_from_this();
}

void HostTokenAuthRequest::HostBeginTokenAuth()
{
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    HostBeginTokenAuthInput input = {};
    input.requestId = GetRequestId();
    input.scheduleId = GetScheduleId();
    input.templateId = templateId_;
    input.fwkMsg = fwkMsg_;
    HostBeginTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostBeginTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostBeginTokenAuth failed ret=%{public}d", GetDescription(), ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }
    needEndTokenAuth_ = true;

    bool sendRet = SendTokenAuthRequest(output.tokenAuthRequest);
    if (!sendRet) {
        IAM_LOGE("%{public}s SendTokenAuthRequest failed", GetDescription());
        errorGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    errorGuard.Cancel();
}

bool HostTokenAuthRequest::SendTokenAuthRequest(const std::vector<uint8_t> &tokenAuthRequest)
{
    DeviceKey hostDeviceKey = {};
    auto localDeviceKey = GetCrossDeviceCommManager().GetLocalDeviceKeyByConnectionName(GetConnectionName());
    if (localDeviceKey.has_value()) {
        hostDeviceKey = *localDeviceKey;
    }
    hostDeviceKey.deviceUserId = hostUserId_;
    TokenAuthRequest requestMsg = { .hostDeviceKey = hostDeviceKey,
        .companionUserId = companionUserId_,
        .extraInfo = tokenAuthRequest };
    Attributes request = {};
    bool encodeRet = EncodeTokenAuthRequest(requestMsg, request);
    ENSURE_OR_RETURN_VAL(encodeRet, false);

    auto weakSelf = std::weak_ptr<HostTokenAuthRequest>(shared_from_this());
    bool sendRet = GetCrossDeviceCommManager().SendMessage(GetConnectionName(), MessageType::TOKEN_AUTH, request,
        [weakSelf](const Attributes &reply) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleTokenAuthReply(reply);
        });
    if (!sendRet) {
        IAM_LOGE("%{public}s SendMessage failed", GetDescription());
        return false;
    }
    return true;
}

void HostTokenAuthRequest::HandleTokenAuthReply(const Attributes &reply)
{
    IAM_LOGI("%{public}s", GetDescription());
    ErrorGuard errorGuard([this](ResultCode resultCode) { CompleteWithError(resultCode); });

    auto replyOpt = DecodeTokenAuthReply(reply);
    if (!replyOpt.has_value()) {
        IAM_LOGE("%{public}s decode reply failed", GetDescription());
        return;
    }
    const auto &replyMsg = *replyOpt;
    if (replyMsg.result != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s companion token auth failed result=%{public}d", GetDescription(),
            static_cast<int32_t>(replyMsg.result));

        GetCompanionManager().SetCompanionTokenAtl(templateId_, std::nullopt);

        errorGuard.UpdateErrorCode(replyMsg.result);
        return;
    }

    std::vector<uint8_t> tokenAuthReply = replyMsg.extraInfo;
    std::vector<uint8_t> fwkMsg = {};
    bool endTokenAuthRet = SecureAgentEndTokenAuth(tokenAuthReply, fwkMsg);
    if (!endTokenAuthRet) {
        IAM_LOGE("%{public}s SecureAgentEndTokenAuth failed", GetDescription());

        return;
    }
    needEndTokenAuth_ = false;
    errorGuard.Cancel();
    CompleteWithSuccess(fwkMsg);
}

bool HostTokenAuthRequest::SecureAgentEndTokenAuth(const std::vector<uint8_t> &tokenAuthReply,
    std::vector<uint8_t> &outFwkMsg)
{
    HostEndTokenAuthInput input = {};
    input.requestId = GetRequestId();
    input.templateId = templateId_;
    input.secureProtocolId = secureProtocolId_;
    input.tokenAuthReply = tokenAuthReply;

    HostEndTokenAuthOutput output = {};
    ResultCode ret = GetSecurityAgent().HostEndTokenAuth(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostEndTokenAuth failed ret=%{public}d", GetDescription(), ret);
        return false;
    }
    outFwkMsg.swap(output.fwkMsg);
    return true;
}

void HostTokenAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
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

void HostTokenAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s: token auth request failed, result=%{public}d", GetDescription(), result);

    if (needEndTokenAuth_) {
        std::vector<uint8_t> fwkMsg = {};
        (void)SecureAgentEndTokenAuth({}, fwkMsg);
        needEndTokenAuth_ = false;
    }
    InvokeCallback(result, {});
    Destroy();
}

void HostTokenAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    Destroy();
}

uint32_t HostTokenAuthRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostTokenAuthRequest
}

bool HostTokenAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostTokenAuthRequest to same peer device preempts existing one
    if (newRequestType == RequestType::HOST_TOKEN_AUTH_REQUEST && GetPeerDeviceKey() == newPeerDevice) {
        IAM_LOGI("%{public}s: preempted by new HostTokenAuth to same device", GetDescription());
        return true;
    }

    return false;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
