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

#include <atomic>
#include <cstdint>
#include <future>
#include <optional>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include <nlohmann/json.hpp>

#include "adapter_manager.h"
#include "cda_attributes.h"
#include "common_defines.h"
#include "companion_device_auth_executor_callback.h"
#include "companion_manager.h"
#include "host_add_companion_request.h"
#include "host_binding_manager.h"
#include "host_remove_host_binding_request.h"
#include "host_token_auth_request.h"
#include "pending_issue_token_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "service_common.h"
#include "task_runner.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_CDA_ALL_IN_ONE_EXECUTOR

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
constexpr size_t UINT8_BIT_WIDTH = 8;
constexpr int32_t COMMAND_ID_SET_COMPANION_INVALID = 10001;
} // namespace

struct CdaAuthenticateParam {
    std::optional<uint32_t> tokenId;
    std::optional<BusinessId> businessId;
    WidgetAuthParam delegateAuthParam;
};

class CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutorInner : public NoCopyable {
public:
    CompanionDeviceAuthAllInOneExecutorInner()
    {
        IAM_LOGI("start");
        pendingIssueTokenManager_ = std::make_shared<PendingIssueTokenManager>();
        ENSURE_OR_RETURN(pendingIssueTokenManager_ != nullptr);
    }

    ~CompanionDeviceAuthAllInOneExecutorInner() = default;

    FwkResultCode GetExecutorInfo(FwkExecutorInfo &info);
    FwkResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo);
    FwkResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg);
    FwkResultCode Enroll(uint64_t scheduleId, const FwkEnrollParam &param,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &fwkParam,
        const CdaAuthenticateParam &cdaParam, const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode Delete(const std::vector<uint64_t> &templateIdList);
    FwkResultCode Cancel(uint64_t scheduleId);
    FwkResultCode SendCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj);
    FwkResultCode GetProperty(const std::vector<uint64_t> &templateIdList, const std::vector<FwkAttributeKey> &keys,
        FwkProperty &property);
    void HandleFreezeRelatedCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo);
    void HandleSetCompanionInvalid(const std::vector<uint8_t> &extraInfo);

private:
    std::optional<FreezeCommand> DecodeFreezeCommand(const std::vector<uint8_t> &dataTlv);

    std::shared_ptr<PendingIssueTokenManager> pendingIssueTokenManager_;
};

using Inner = CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutorInner;

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
    RegisterFinishInput input {};
    input.templateIdList.assign(templateIdList.begin(), templateIdList.end());
    input.fwkPublicKey = frameworkPublicKey;
    input.fwkMsg = extraInfo;
    ResultCode result = GetSecurityAgent().HostOnRegisterFinish(input);
    if (result != ResultCode::SUCCESS) {
        IAM_LOGE("Fail:%{public}d", result);
        return FwkResultCode::GENERAL_ERROR;
    }

    GetCompanionManager().ReconcileWithSecurityAgent();

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

    IAM_LOGI("scheduleId:%{public}s", ToHexString(scheduleId).c_str());
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(callbackObj);
    ENSURE_OR_RETURN_VAL(callback != nullptr, FwkResultCode::GENERAL_ERROR);
    FwkResultCallback requestCallback = [callback](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (*callback)(result, extraInfo);
    };

    // Build fwkMsg with additionalInfo
    std::vector<uint8_t> fwkMsg = param.extraInfo;
    if (!param.additionalInfo.empty()) {
        FwkAttribute fwkAttributes(fwkMsg);
        fwkAttributes.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, param.additionalInfo);
        fwkMsg = fwkAttributes.Serialize();
    }

    auto request = GetRequestFactory().CreateHostAddCompanionRequest(scheduleId, fwkMsg, param.tokenId,
        param.additionalInfo, std::move(requestCallback));
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

FwkResultCode Inner::Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &fwkParam,
    const CdaAuthenticateParam &cdaParam, const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    if (callbackObj == nullptr) {
        IAM_LOGE("callbackObj is null");
        return FwkResultCode::GENERAL_ERROR;
    }

    if (fwkParam.templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return FwkResultCode::NO_VALID_CREDENTIAL;
    }

    IAM_LOGI("scheduleId:%{public}s", ToHexString(scheduleId).c_str());
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(callbackObj);
    ENSURE_OR_RETURN_VAL(callback != nullptr, FwkResultCode::GENERAL_ERROR);
    FwkResultCallback requestCallback = [callback](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (*callback)(result, extraInfo);
    };

    HostMixAuthParams params = { scheduleId, fwkParam.extraInfo, fwkParam.userId, fwkParam.templateIdList,
        cdaParam.tokenId, cdaParam.businessId, fwkParam.authIntent, fwkParam.authScene, fwkParam.title,
        cdaParam.delegateAuthParam };
    auto request = GetRequestFactory().CreateHostMixAuthRequest(params, std::move(requestCallback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostMixAuthRequest failed");
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

FwkResultCode Inner::Delete(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("start");
    if (templateIdList.empty()) {
        IAM_LOGE("templateIdList is empty");
        return FwkResultCode::GENERAL_ERROR;
    }

    for (TemplateId templateId : templateIdList) {
        ResultCode ret = GetCompanionManager().RemoveCompanion(templateId, true);
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
    IAM_LOGI("start, scheduleId:%{public}s", ToHexString(scheduleId).c_str());
    if (!GetRequestManager().CancelRequestByScheduleId(scheduleId)) {
        IAM_LOGE("cancel request not found or already completed");
    }

    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::SendCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<FwkIExecuteCallback> &callbackObj)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN_VAL(callbackObj != nullptr, FwkResultCode::GENERAL_ERROR);
    // The framework does not interpret the ResultCode in OnResult; always return SUCCESS.
    // OnResult is called before processing so that the callback fires at a deterministic point.
    callbackObj->OnResult(FwkResultCode::SUCCESS, {});
    if (commandId == static_cast<FwkPropertyMode>(COMMAND_ID_SET_COMPANION_INVALID)) {
        HandleSetCompanionInvalid(extraInfo);
    } else if (commandId == FwkPropertyMode::PROPERTY_MODE_FREEZE ||
        commandId == FwkPropertyMode::PROPERTY_MODE_UNFREEZE) {
        HandleFreezeRelatedCommand(commandId, extraInfo);
    } else {
        IAM_LOGI("SendCommand not implemented for commandId=%{public}d", commandId);
    }
    IAM_LOGI("end");
    return FwkResultCode::SUCCESS;
}

FwkResultCode Inner::GetProperty(const std::vector<uint64_t> &templateIdList, const std::vector<FwkAttributeKey> &keys,
    FwkProperty &property)
{
    IAM_LOGI("start");
    (void)templateIdList;
    (void)keys;
    property.authSubType = 0;
    property.enrollmentProgress.clear();
    property.sensorInfo.clear();
    property.nextFailLockoutDuration = 0;
    property.credentialLength = 0;
    bool blocked = GetMiscManager().IsCompanionAuthBlocked();
    IAM_LOGI("companion auth blocked %{public}d", blocked);
    if (blocked) {
        property.lockoutDuration = INT32_MAX;
        property.remainAttempts = 0;
    } else {
        property.lockoutDuration = 0;
        property.remainAttempts = INT32_MAX;
    }
    return FwkResultCode::SUCCESS;
}

void Inner::HandleSetCompanionInvalid(const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start");
    std::string jsonStr(extraInfo.begin(), extraInfo.end());
    try {
        auto json = nlohmann::json::parse(jsonStr);
        if (!json.is_object() || !json.contains("templateId")) {
            IAM_LOGE("invalid extraInfo: not an object or missing templateId");
            return;
        }
        auto &val = json["templateId"];
        // JS Uint8Array serializes as {"0":173,"1":157,...}; accept both formats
        bool isArray = val.is_array();
        bool isObj = val.is_object();
        if (!isArray && !isObj) {
            IAM_LOGE("invalid templateId: not an array or object");
            return;
        }
        if (isArray && val.size() != sizeof(uint64_t)) {
            IAM_LOGE("invalid templateId: array size %{public}zu != %{public}zu", val.size(), sizeof(uint64_t));
            return;
        }
        uint64_t templateId = 0;
        for (size_t i = 0; i < sizeof(uint64_t); ++i) {
            if (isObj && !val.contains(std::to_string(i))) {
                IAM_LOGE("invalid templateId: missing key %{public}zu", i);
                return;
            }
            auto &elem = isArray ? val[i] : val[std::to_string(i)];
            if (!elem.is_number_integer() || elem.get<int64_t>() < 0 || elem.get<int64_t>() > UINT8_MAX) {
                IAM_LOGE("invalid templateId: element %{public}zu is not a valid uint8", i);
                return;
            }
            templateId |= static_cast<uint64_t>(elem.get<uint8_t>()) << (i * UINT8_BIT_WIDTH);
        }
        IAM_LOGI("setting companion invalid, templateId %{public}s", GET_MASKED_NUM_CSTR(templateId));
        GetCompanionManager().SetTemplateInvalid(templateId, "fwkCommand");
    } catch (const nlohmann::json::exception &) {
        IAM_LOGE("failed to parse extraInfo as JSON");
    }
    IAM_LOGI("end");
}

std::optional<FreezeCommand> Inner::DecodeFreezeCommand(const std::vector<uint8_t> &dataTlv)
{
    FreezeCommand freezeCommand {};
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

void Inner::HandleFreezeRelatedCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo)
{
    Attributes attrs(extraInfo);
    std::vector<uint8_t> rootTlv;
    bool getRootTlvRet = attrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    ENSURE_OR_RETURN(getRootTlvRet);

    Attributes rootTlvAttrs(rootTlv);
    std::vector<uint8_t> dataTlv;
    bool getDataTlvRet = rootTlvAttrs.GetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    ENSURE_OR_RETURN(getDataTlvRet);

    std::optional<FreezeCommand> freezeCommandOpt = DecodeFreezeCommand(dataTlv);
    ENSURE_OR_RETURN(freezeCommandOpt.has_value());

    const FreezeCommand &freezeCommand = freezeCommandOpt.value();
    if (static_cast<AuthType>(freezeCommand.authTypeValue) != AuthType::COMPANION_DEVICE) {
        IAM_LOGI("AuthType %{public}u is not companion device", freezeCommand.authTypeValue);
        return;
    }

    AuthType lockStateAuthType = static_cast<AuthType>(freezeCommand.lockStateAuthTypeValue);
    if (lockStateAuthType != AuthType::PIN && lockStateAuthType != AuthType::FACE &&
        lockStateAuthType != AuthType::FINGERPRINT) {
        IAM_LOGI("AuthType %{public}u is ignored", freezeCommand.lockStateAuthTypeValue);
        return;
    }

    IAM_LOGI("receive commandId:%{public}d, AuthType:%{public}u, templateIdList size:%{public}zu, userId:%{public}d",
        commandId, freezeCommand.lockStateAuthTypeValue, freezeCommand.templateIdList.size(), freezeCommand.userId);

    ENSURE_OR_RETURN(pendingIssueTokenManager_ != nullptr);
    if (commandId == FwkPropertyMode::PROPERTY_MODE_FREEZE && lockStateAuthType == AuthType::PIN) {
        GetMiscManager().SetCompanionAuthBlocked(true);
        pendingIssueTokenManager_->CancelByUserId(freezeCommand.userId);
        for (const auto &templateId : freezeCommand.templateIdList) {
            GetCompanionManager().SetCompanionTokenAuthAtl(templateId, std::nullopt);
        }
        GetHostBindingManager().RevokeTokens(freezeCommand.userId);
    } else if (commandId == FwkPropertyMode::PROPERTY_MODE_UNFREEZE) {
        GetMiscManager().SetCompanionAuthBlocked(false);
        if (GetUserIdManager().GetActiveUserId() == freezeCommand.userId) {
            pendingIssueTokenManager_->CancelByUserId(freezeCommand.userId);
            GetCompanionManager().StartIssueTokenRequests(freezeCommand.templateIdList,
                freezeCommand.lockStateAuthTypeValue, extraInfo);
            GetHostBindingManager().StartObtainTokenRequests(freezeCommand.userId, freezeCommand.lockStateAuthTypeValue,
                extraInfo);
        } else {
            IAM_LOGI("userId %{public}d mismatch active=%{public}d, deferring", freezeCommand.userId,
                GetUserIdManager().GetActiveUserId());
            pendingIssueTokenManager_->Defer(freezeCommand, extraInfo);
        }
    }
}

CompanionDeviceAuthAllInOneExecutor::CompanionDeviceAuthAllInOneExecutor()
{
    IAM_LOGI("start");
    inner_ = std::make_shared<CompanionDeviceAuthAllInOneExecutorInner>();
    ENSURE_OR_RETURN(inner_ != nullptr);
}

std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> CompanionDeviceAuthAllInOneExecutor::Create()
{
    IAM_LOGI("start");
    auto executor = std::shared_ptr<CompanionDeviceAuthAllInOneExecutor>(new CompanionDeviceAuthAllInOneExecutor());
    if (executor == nullptr) {
        IAM_LOGE("Failed to create CompanionDeviceAuthAllInOneExecutor");
        return nullptr;
    }
    return executor;
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::GetExecutorInfo(FwkExecutorInfo &info)
{
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    auto infoBox = std::make_shared<FwkExecutorInfo>();
    ENSURE_OR_RETURN_VAL(infoBox != nullptr, FwkResultCode::GENERAL_ERROR);
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
    ENSURE_OR_RETURN_VAL(callbackObj != nullptr, FwkResultCode::GENERAL_ERROR);
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
    ENSURE_OR_RETURN_VAL(callbackObj != nullptr, FwkResultCode::GENERAL_ERROR);
    IAM_LOGI("start");
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);

    CdaAuthenticateParam cdaParam = {};
    if (SupportDeviceSelect(param.authIntent)) {
        cdaParam.tokenId = param.tokenId;
    }
    cdaParam.businessId = GetAuthBusinessId(param.authIntent);
    cdaParam.delegateAuthParam = GetWidgetAuthParam(param.authIntent);

    return RunOnResidentSync([inner, scheduleId, fwkParam = param, cdaParam, callbackObj]() {
        return inner->Authenticate(scheduleId, fwkParam, cdaParam, callbackObj);
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
    auto inner = inner_;
    ENSURE_OR_RETURN_VAL(inner != nullptr, FwkResultCode::GENERAL_ERROR);
    auto propertyBox = std::make_shared<FwkProperty>();
    ENSURE_OR_RETURN_VAL(propertyBox != nullptr, FwkResultCode::GENERAL_ERROR);
    FwkResultCode ret = RunOnResidentSync([inner, templateIdListCopy = templateIdList, keysCopy = keys, propertyBox]() {
        return inner->GetProperty(templateIdListCopy, keysCopy, *propertyBox);
    });
    property = *propertyBox;
    return ret;
}

FwkResultCode CompanionDeviceAuthAllInOneExecutor::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    IAM_LOGI("start");
    (void)templateIdList;
    return FwkResultCode::SUCCESS;
}

bool CompanionDeviceAuthAllInOneExecutor::SupportDeviceSelect(int32_t authIntent) const
{
    static_cast<void>(authIntent);
    IAM_LOGI("device select is not supported");
    return false;
}

std::optional<BusinessId> CompanionDeviceAuthAllInOneExecutor::GetAuthBusinessId(int32_t authIntent) const
{
    static_cast<void>(authIntent);
    IAM_LOGI("get device business id is not supported");
    return std::nullopt;
}

WidgetAuthParam CompanionDeviceAuthAllInOneExecutor::GetWidgetAuthParam(int32_t authIntent) const
{
    static_cast<void>(authIntent);
    IAM_LOGI("get delegate auth param is not supported");
    WidgetAuthParam authParam = {};
    authParam.authTypes = std::vector<UserAuth::AuthType> { UserAuth::AuthType::PIN, UserAuth::AuthType::FACE,
        UserAuth::AuthType::FINGERPRINT };
    return authParam;
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
    ENSURE_OR_RETURN_VAL(resultPromise != nullptr, FwkResultCode::GENERAL_ERROR);
    auto future = resultPromise->get_future();
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    ENSURE_OR_RETURN_VAL(cancelled != nullptr, FwkResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [taskFunc = std::move(func), promise = resultPromise, cancelled]() mutable {
            if (cancelled->load()) {
                IAM_LOGI("RunOnResidentSync task cancelled before execution");
                return;
            }
            try {
                promise->set_value(taskFunc());
            } catch (...) {
                try {
                    promise->set_exception(std::current_exception());
                } catch (...) {
                    IAM_LOGE("RunOnResidentSync set_exception failed");
                }
            }
        });

    std::future_status status = future.wait_for(std::chrono::seconds(timeoutSec));
    if (status != std::future_status::ready) {
        IAM_LOGE("RunOnResidentSync timeout - task not completed in %{public}u second, status: %{public}d", timeoutSec,
            static_cast<int32_t>(status));
        cancelled->store(true);
        return FwkResultCode::TIMEOUT;
    }

    return future.get();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
