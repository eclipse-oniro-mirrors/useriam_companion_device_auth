/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "companion_device_auth_all_in_one_executor.h"

#include <cstdint>
#include <future>
#include <optional>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "cda_attributes.h"
#include "common_defines.h"
#include "companion_device_auth_executor_callback.h"
#include "companion_manager.h"
#include "host_add_companion_request.h"
#include "host_binding_manager.h"
#include "host_remove_host_binding_request.h"
#include "host_token_auth_request.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "service_common.h"
#include "task_runner.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t ATTR_ROOT = 100000;
const uint32_t ATTR_TEMPLATE_ID_LIST = 100007;
const uint32_t ATTR_DATA = 100020;
const uint32_t ATTR_AUTH_TYPE = 100024;
const uint32_t ATTR_USER_ID = 100041;
const uint32_t ATTR_LOCK_STATE_AUTH_TYPE = 100075;
} // namespace

using Inner = CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutorInner;

struct FreezeCommand {
    uint32_t authTypeValue = 0;
    uint32_t lockStateAuthTypeValue = 0;
    int32_t userId = 0;
    std::vector<uint64_t> templateIdList;
};

class CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutorInner : public NoCopyable {
public:
    CompanionDeviceAuthAllInOneExecutorInner()
    {
        IAM_LOGI("start");
    }

    ~CompanionDeviceAuthAllInOneExecutorInner() = default;

    FwkResultCode GetExecutorInfo(FwkExecutorInfo &info);
    FwkResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo);
    FwkResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg);
    FwkResultCode Enroll(uint64_t scheduleId, const FwkEnrollParam &param,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &param,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode Delete(const std::vector<uint64_t> &templateIdList);
    FwkResultCode Cancel(uint64_t scheduleId);
    FwkResultCode SendCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode HandleFreezeRelatedCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo);

private:
    std::optional<FreezeCommand> DecodeFreezeCommand(const std::vector<uint8_t> &dataTlv);
};

FwkResultCode Inner::GetExecutorInfo(FwkExecutorInfo &info)
{
    IAM_LOGI("start");
    const uint16_t sensorHint = 1;
    HostGetExecutorInfoOutput output = {};
    ResultCode result = GetSecurityAgent().HostGetExecutorInfo(output);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("HostGetExecutorInfo fail ret=%{public}d", result);
        return FwkResultCode::GENERAL_ERROR;
    }
    info.authType = UserAuth::AuthType::COMPANION_DEVICE;
    info.executorRole = UserAuth::ExecutorRole::ALL_IN_ONE;
    info.executorSensorHint = sensorHint;
    info.executorMatcher = 0;
    info.esl = static_cast<UserAuth::ExecutorSecureLevel>(output.executorInfo.esl);
    info.maxTemplateAcl = output.executorInfo.maxTemplateAcl;
    info.publicKey = output.executorInfo.publicKey;
    info.deviceUdid = "";
    info.signedRemoteExecutorInfo = {};

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    RegisterFinishInput input;
    input.templateIdList.assign(templateIdList.begin(), templateIdList.end());
    input.fwkPublicKey = frameworkPublicKey;
    input.fwkMsg = extraInfo;
    ResultCode result = GetSecurityAgent().HostOnRegisterFinish(input);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("Fail:%{public}d", result);
        return FwkResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    (void)scheduleId;
    (void)srcRole;
    (void)msg;
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::Enroll(uint64_t scheduleId, const FwkEnrollParam &param,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return FwkResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("scheduleId:%{public}s", GET_TRUNCATED_CSTR(scheduleId));
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(callbackObj);
    FwkResultCallback requestCallback = [callback](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (*callback)(result, extraInfo);
    };

    auto request = GetRequestFactory().CreateHostAddCompanionRequest(scheduleId, param.extraInfo, param.tokenId,
        std::move(requestCallback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostAddCompanionRequest failed");
        callbackObj->OnResult(FwkResultCode::GENERAL_ERROR, {});
        return FwkResultCode::GENERAL_ERROR;
    }

    bool result = GetRequestManager().Start(request);
    if (!result) {
        IAM_LOGE("request Start failed");
        callbackObj->OnResult(FwkResultCode::GENERAL_ERROR, {});
        return FwkResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &param,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return FwkResultCode::GENERAL_ERROR;
    }

    if (param.templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return FwkResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("scheduleId:%{public}s", GET_TRUNCATED_CSTR(scheduleId));
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(callbackObj);
    FwkResultCallback requestCallback = [callback](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (*callback)(result, extraInfo);
    };

    auto request = GetRequestFactory().CreateHostMixAuthRequest(scheduleId, param.extraInfo, param.userId,
        param.templateIdList, std::move(requestCallback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostMixAuthRequest failed");
        callbackObj->OnResult(FwkResultCode::GENERAL_ERROR, {});
        return FwkResultCode::SUCCESS;
    }

    bool result = GetRequestManager().Start(request);
    if (!result) {
        IAM_LOGE("request Start failed");
        callbackObj->OnResult(FwkResultCode::GENERAL_ERROR, {});
        return FwkResultCode::SUCCESS;
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::Delete(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("start");
    if (templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return FwkResultCode::GENERAL_ERROR;
    }

    for (TemplateId templateId : templateIdList) {
        ResultCode ret = GetCompanionManager().RemoveCompanion(templateId);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("RemoveCompanion failed for templateId %{public}s, ret=%{public}d",
                GET_MASKED_NUM_CSTR(templateId), ret);
            continue;
        }
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    IAM_LOGI("scheduleId:%{public}s", GET_TRUNCATED_CSTR(scheduleId));
    if (!GetRequestManager().CancelRequestByScheduleId(scheduleId)) {
        IAM_LOGE("Failed cancel request");
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::SendCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN_VAL(callbackObj != nullptr, FwkResultCode::GENERAL_ERROR);
    callbackObj->OnResult(FwkResultCode::SUCCESS, {});

    if (commandId != FwkPropertyMode::PROPERTY_MODE_FREEZE && commandId != FwkPropertyMode::PROPERTY_MODE_UNFREEZE) {
        IAM_LOGI("SendCommand not implemented for commandId=%{public}d, returning success", commandId);
        return FwkResultCode::SUCCESS;
    }

    FwkResultCode ret = HandleFreezeRelatedCommand(commandId, extraInfo);
    IAM_LOGI("end");
    return ret;
}

std::optional<FreezeCommand> Inner::DecodeFreezeCommand(const std::vector<uint8_t> &dataTlv)
{
    FreezeCommand freezeCommand;
    Attributes dataTlvAttrs(dataTlv);
    bool getAuthTypeRet =
        dataTlvAttrs.GetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE), freezeCommand.authTypeValue);
    ENSURE_OR_RETURN_VAL(getAuthTypeRet, std::nullopt);

    bool getLockStateAuthTypeRet = dataTlvAttrs.GetUint32Value(
        static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE), freezeCommand.lockStateAuthTypeValue);
    ENSURE_OR_RETURN_VAL(getLockStateAuthTypeRet, std::nullopt);

    bool getUserIdRet =
        dataTlvAttrs.GetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), freezeCommand.userId);
    ENSURE_OR_RETURN_VAL(getUserIdRet, std::nullopt);

    bool getTemplateIdListRet = dataTlvAttrs.GetUint64ArrayValue(
        static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), freezeCommand.templateIdList);
    ENSURE_OR_RETURN_VAL(getTemplateIdListRet, std::nullopt);

    return freezeCommand;
}

FwkResultCode Inner::HandleFreezeRelatedCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo)
{
    Attributes attrs(extraInfo);
    std::vector<uint8_t> rootTlv;
    bool getRootTlvRet = attrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    ENSURE_OR_RETURN_VAL(getRootTlvRet, FwkResultCode::GENERAL_ERROR);

    Attributes rootTlvAttrs(rootTlv);
    std::vector<uint8_t> dataTlv;
    bool getDataTlvRet = rootTlvAttrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    ENSURE_OR_RETURN_VAL(getDataTlvRet, FwkResultCode::GENERAL_ERROR);

    std::optional<FreezeCommand> freezeCommandOpt = DecodeFreezeCommand(dataTlv);
    ENSURE_OR_RETURN_VAL(freezeCommandOpt.has_value(), FwkResultCode::GENERAL_ERROR);

    const FreezeCommand &freezeCommand = freezeCommandOpt.value();
    if (static_cast<AuthType>(freezeCommand.authTypeValue) != AuthType::COMPANION_DEVICE) {
        IAM_LOGI("AuthType %{public}u is not companion device", freezeCommand.authTypeValue);
        return FwkResultCode::GENERAL_ERROR;
    }

    AuthType lockStateAuthType = static_cast<AuthType>(freezeCommand.lockStateAuthTypeValue);
    if (lockStateAuthType != AuthType::PIN && lockStateAuthType != AuthType::FACE &&
        lockStateAuthType != AuthType::FINGERPRINT) {
        IAM_LOGI("AuthType %{public}u is ignored", freezeCommand.lockStateAuthTypeValue);
        return FwkResultCode::SUCCESS;
    }

    IAM_LOGI("receive commandId:%{public}d, AuthType:%{public}u, templateIdList size:%{public}zu, userId:%{public}d",
        commandId, freezeCommand.lockStateAuthTypeValue, freezeCommand.templateIdList.size(), freezeCommand.userId);

    if (commandId == FwkPropertyMode::PROPERTY_MODE_FREEZE && lockStateAuthType == AuthType::PIN) {
        for (const auto &templateId : freezeCommand.templateIdList) {
            GetCompanionManager().SetCompanionTokenAtl(templateId, std::nullopt);
        }
        GetHostBindingManager().RevokeTokens(freezeCommand.userId);
    } else if (commandId == FwkPropertyMode::PROPERTY_MODE_UNFREEZE) {
        if (GetUserIdManager().GetActiveUserId() != freezeCommand.userId) {
            IAM_LOGE("userId %{public}d mismatch with active user id %{public}d, skip", freezeCommand.userId,
                GetUserIdManager().GetActiveUserId());
            return FwkResultCode::SUCCESS;
        }
        GetCompanionManager().StartIssueTokenRequests(freezeCommand.templateIdList, extraInfo);
        GetHostBindingManager().StartObtainTokenRequests(freezeCommand.userId, extraInfo);
    }

    return FwkResultCode::SUCCESS;
}

CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutor()
{
    IAM_LOGI("start");
    inner_ = std::make_shared<CompanionDeviceAuthAllInOneExecutorInner>();
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::GetExecutorInfo(FwkExecutorInfo &info)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    auto infoBox = std::make_shared<FwkExecutorInfo>();
    FwkResultCode ret = RunOnResidentSync([inner, infoBox]() { return inner->GetExecutorInfo(*infoBox); });
    info = *infoBox;
    return ret;
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
    const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync([inner, templateIdListCopy = templateIdList, fwkPublicKeyCopy = frameworkPublicKey,
                                 extraInfoCopy = extraInfo]() mutable {
        return inner->OnRegisterFinish(templateIdListCopy, fwkPublicKeyCopy, extraInfoCopy);
    });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::SendMessage(uint64_t scheduleId, int32_t srcRole,
    const std::vector<uint8_t> &msg)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync(
        [inner, scheduleId, srcRole, msgCopy = msg]() { return inner->SendMessage(scheduleId, srcRole, msgCopy); });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::Enroll(uint64_t scheduleId, const FwkEnrollParam &param,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync([inner, scheduleId, paramCopy = param, cbCopy = callbackObj]() {
        return inner->Enroll(scheduleId, paramCopy, cbCopy);
    });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &param,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync([inner, scheduleId, paramCopy = param, cbCopy = callbackObj]() {
        return inner->Authenticate(scheduleId, paramCopy, cbCopy);
    });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::Delete(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync(
        [inner, templateIdListCopy = templateIdList]() { return inner->Delete(templateIdListCopy); });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::Cancel(uint64_t scheduleId)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync([inner, scheduleId]() { return inner->Cancel(scheduleId); });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::SendCommand(FwkPropertyMode commandId,
    const std::vector<uint8_t> &extraInfo, const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    return RunOnResidentSync([inner, commandId, extraInfoCopy = extraInfo, cbCopy = callbackObj]() {
        return inner->SendCommand(commandId, extraInfoCopy, cbCopy);
    });
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::GetProperty(const std::vector<uint64_t> &templateIdList,
    const std::vector<FwkAttributeKey> &keys, FwkProperty &property)
{
    IAM_LOGI("start");
    (void)templateIdList;
    (void)keys;
    property.authSubType = 0;
    property.lockoutDuration = 0;
    property.remainAttempts = INT32_MAX;
    property.enrollmentProgress.clear();
    property.sensorInfo.clear();
    property.nextFailLockoutDuration = 0;
    property.credentialLength = 0;
    return FwkResultCode::SUCCESS;
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("start");
    (void)templateIdList;
    return FwkResultCode::SUCCESS;
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::RunOnResidentSync(std::function<FwkResultCode()> func,
    uint32_t timeoutSec)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN_VAL(inner_ != nullptr, FwkResultCode::GENERAL_ERROR);
    if (TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()) {
        IAM_LOGI("running on resident task runner");
        return func();
    }

    IAM_LOGI("post function to default task runner");
    auto resultPromise = std::make_shared<std::promise<FwkResultCode>>();
    auto future = resultPromise->get_future();

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [taskFunc = std::move(func), promise = resultPromise]() mutable {
            try {
                promise->set_value(taskFunc());
            } catch (...) {
                IAM_LOGE("RunOnResidentSync task exception");
            }
        });

    std::future_status status = future.wait_for(std::chrono::seconds(timeoutSec));
    if (status != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second, status: %{public}d", timeoutSec,
            static_cast<int>(status));
        return FwkResultCode::TIMEOUT;
    }

    return future.get();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
