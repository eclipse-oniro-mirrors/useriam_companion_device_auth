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

#include "napi/native_api.h"
#include "napi/native_common.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "tokenid_kit.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_client.h"
#include "companion_device_auth_common_defines.h"
#include "companion_device_auth_napi_helper.h"
#include "idevice_select_callback.h"
#include "napi_device_select_callback.h"
#include "napi_passcode_prompt_callback.h"
#include "status_monitor.h"

#define LOG_TAG "CDA_NAPI"
#define LOG_FILE_ID LOG_FILE_CDA_NAPI_ENTRY

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using NapiStatusMonitor = StatusMonitor<JsRefHolder, JsRefHolder, JsRefHolder>;
using NapiTemplateStatusCallback = TemplateStatusCallbackWrapper<JsRefHolder>;
using NapiAvailableDeviceStatusCallback = AvailableDeviceStatusCallbackWrapper<JsRefHolder>;
using NapiContinuousAuthStatusCallback = ContinuousAuthStatusCallbackWrapper<JsRefHolder>;

namespace {
int32_t CheckPermission(const std::string &permission)
{
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOW_MASK;

    if (AccessTokenKit::VerifyAccessToken(tokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("check permission %{public}s failed", permission.c_str());
        return CHECK_PERMISSION_FAILED;
    }

    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (!checkRet || callingType != Security::AccessToken::TOKEN_HAP) {
        IAM_LOGE("the caller is not system application");
        return CHECK_SYSTEM_PERMISSION_FAILED;
    }
    return SUCCESS;
}

std::optional<int32_t> GetUserId(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_ONE) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d argc:%{public}zu", status, argc);
        return std::nullopt;
    }
    int32_t userId {};
    status = CompanionDeviceAuthNapiHelper::GetInt32Value(env, argv[PARAM0], userId);
    if (status != napi_ok) {
        IAM_LOGE("GetInt32Value fail, ret:%{public}d", status);
        return std::nullopt;
    }
    return userId;
}

std::optional<napi_ref> GetCallbackRef(napi_env env, napi_callback_info info)
{
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return std::nullopt;
    }
    if (argc == 0) {
        // No callback provided, return nullptr ref for Off* functions to unsubscribe all
        return static_cast<napi_ref>(nullptr);
    }
    if (argc == ARGS_ONE) {
        napi_ref ref = nullptr;
        status = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, argv[PARAM0], ref);
        if (status != napi_ok || ref == nullptr) {
            IAM_LOGE("GetFunctionRef fail %{public}d", status);
            return std::nullopt;
        }
        return ref;
    }
    IAM_LOGE("invalid param, argc:%{public}zu", argc);
    return std::nullopt;
}

bool UnwrapStatusMonitor(napi_env env, napi_callback_info info, NapiStatusMonitor **statusMonitor)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { nullptr };
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return false;
    }
    napi_valuetype thisType = napi_undefined;
    ret = napi_typeof(env, thisVar, &thisType);
    if (ret != napi_ok || thisType != napi_object) {
        IAM_LOGE("thisVar is not object");
        return false;
    }
    ret = napi_unwrap(env, thisVar, reinterpret_cast<void **>(statusMonitor));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        return false;
    }
    if (*statusMonitor == nullptr) {
        IAM_LOGE("statusMonitor is null");
        return false;
    }
    return true;
}

void DoPromise(napi_env env, napi_deferred promise, napi_value promiseValue, int32_t result)
{
    IAM_LOGI("start");
    if (result == SUCCESS) {
        napi_value finalValue = promiseValue;
        if (promiseValue == nullptr) {
            napi_get_undefined(env, &finalValue);
        }
        napi_status ret = napi_resolve_deferred(env, promise, finalValue);
        if (ret != napi_ok) {
            IAM_LOGE("napi_resolve_deferred failed %{public}d", ret);
        }
    } else {
        napi_reject_deferred(env, promise, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, result));
    }
}

int32_t GetTemplateStatusInternal(napi_env env, napi_callback_info info, napi_value *outTemplateStatusList)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    std::vector<ClientTemplateStatus> clientTemplateStatusList;
    int32_t ret = statusMonitor->GetTemplateStatus(clientTemplateStatusList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
        return ret;
    }

    napi_value templateStatusList =
        CompanionDeviceAuthNapiHelper::ConvertTemplateStatusListToNapiValue(env, clientTemplateStatusList);
    ENSURE_OR_RETURN_VAL(templateStatusList != nullptr, GENERAL_ERROR);
    *outTemplateStatusList = templateStatusList;
    return SUCCESS;
}

napi_value GetTemplateStatus(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value promiseValue = nullptr;
    napi_deferred promiseDeferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &promiseValue));
    if (promiseDeferred == nullptr || promiseValue == nullptr) {
        IAM_LOGE("fail to create promise object");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    napi_value templateStatusList = nullptr;
    int32_t ret = GetTemplateStatusInternal(env, info, &templateStatusList);
    if (ret != SUCCESS) {
        napi_reject_deferred(env, promiseDeferred, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return promiseValue;
    }
    DoPromise(env, promiseDeferred, templateStatusList, ret);
    IAM_LOGI("success");
    return promiseValue;
}

int32_t OnTemplateChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    auto callback = GetCallbackRef(env, info);
    ENSURE_OR_RETURN_VAL(callback && *callback != nullptr, GENERAL_ERROR);

    int32_t ret =
        statusMonitor->OnTemplateChange(std::make_shared<NapiTemplateStatusCallback>(JsRefHolder(env, *callback)));
    if (ret != SUCCESS) {
        IAM_LOGE("OnTemplateChange fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value OnTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OnTemplateChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t OffTemplateChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    auto callback = GetCallbackRef(env, info);
    ENSURE_OR_RETURN_VAL(callback, GENERAL_ERROR);

    std::shared_ptr<NapiTemplateStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiTemplateStatusCallback>(JsRefHolder(env, *callback));
    }
    int32_t ret = statusMonitor->OffTemplateChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffTemplateChange fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value OffTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OffTemplateChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t OnAvailableDeviceChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    auto callback = GetCallbackRef(env, info);
    ENSURE_OR_RETURN_VAL(callback && *callback != nullptr, GENERAL_ERROR);

    int32_t ret = statusMonitor->OnAvailableDeviceChange(
        std::make_shared<NapiAvailableDeviceStatusCallback>(JsRefHolder(env, *callback)));
    if (ret != SUCCESS) {
        IAM_LOGE("OnAvailableDeviceChange fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value OnAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OnAvailableDeviceChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t OffAvailableDeviceChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    auto callback = GetCallbackRef(env, info);
    ENSURE_OR_RETURN_VAL(callback, GENERAL_ERROR);

    std::shared_ptr<NapiAvailableDeviceStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiAvailableDeviceStatusCallback>(JsRefHolder(env, *callback));
    }
    int32_t ret = statusMonitor->OffAvailableDeviceChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffAvailableDeviceChange fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value OffAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OffAvailableDeviceChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

bool ParseTemplateId(napi_env env, napi_value param, std::optional<uint64_t> &templateIdOpt)
{
    bool hasTemplateId = false;
    napi_status status = napi_has_named_property(env, param, "templateId", &hasTemplateId);
    if (status != napi_ok) {
        IAM_LOGE("fail to check templateId property");
        return false;
    }
    if (!hasTemplateId) {
        IAM_LOGI("templateId not provided in ContinuousAuthParam");
        return true;
    }

    napi_value templateIdProperty = nullptr;
    status = napi_get_named_property(env, param, "templateId", &templateIdProperty);
    if (status != napi_ok) {
        IAM_LOGE("fail to get templateId property");
        return false;
    }
    uint64_t templateIdVal {};
    status = CompanionDeviceAuthNapiHelper::ConvertNapiUint8ArrayToUint64(env, templateIdProperty, templateIdVal);
    if (status != napi_ok) {
        IAM_LOGE("ConvertNapiUint8ArrayToUint64 fail, ret:%{public}d", status);
        return false;
    }
    templateIdOpt = templateIdVal;
    return true;
}

bool GetOnContinuousAuthChangeParam(napi_env env, napi_callback_info info, std::optional<uint64_t> &templateIdOpt,
    std::shared_ptr<NapiContinuousAuthStatusCallback> &callback)
{
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return false;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return false;
    }

    napi_valuetype param0Type = napi_undefined;
    status = napi_typeof(env, argv[PARAM0], &param0Type);
    if (status != napi_ok || param0Type != napi_object) {
        IAM_LOGE("argv[0] is not object");
        return false;
    }

    if (!ParseTemplateId(env, argv[PARAM0], templateIdOpt)) {
        return false;
    }

    napi_ref ref = nullptr;
    status = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, argv[PARAM1], ref);
    if (status != napi_ok || ref == nullptr) {
        IAM_LOGE("GetFunctionRef fail %{public}d", status);
        return false;
    }
    callback = std::make_shared<NapiContinuousAuthStatusCallback>(JsRefHolder(env, ref));
    if (callback == nullptr || !callback->GetCallback().IsValid()) {
        IAM_LOGE("generate callback fail");
        CompanionDeviceAuthNapiHelper::DeleteReference(env, ref);
        return false;
    }
    return true;
}

int32_t OnContinuousAuthChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    std::optional<uint64_t> templateIdOpt;
    std::shared_ptr<NapiContinuousAuthStatusCallback> callback;
    bool getParamRet = GetOnContinuousAuthChangeParam(env, info, templateIdOpt, callback);
    ENSURE_OR_RETURN_VAL(getParamRet, GENERAL_ERROR);

    int32_t ret = statusMonitor->OnContinuousAuthChange(templateIdOpt, callback);
    if (ret != SUCCESS) {
        IAM_LOGE("OnContinuousAuthChange fail, ret:%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

napi_value OnContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OnContinuousAuthChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t OffContinuousAuthChangeInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    NapiStatusMonitor *statusMonitor = nullptr;
    bool unwrapRet = UnwrapStatusMonitor(env, info, &statusMonitor);
    ENSURE_OR_RETURN_VAL(unwrapRet, GENERAL_ERROR);

    auto callback = GetCallbackRef(env, info);
    ENSURE_OR_RETURN_VAL(callback, GENERAL_ERROR);

    std::shared_ptr<NapiContinuousAuthStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiContinuousAuthStatusCallback>(JsRefHolder(env, *callback));
    }

    int32_t ret = statusMonitor->OffContinuousAuthChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffContinuousAuthChange fail, ret:%{public}d", ret);
        return ret;
    }
    return SUCCESS;
}

napi_value OffContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = OffContinuousAuthChangeInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value StatusMonitorConstructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    auto userId = GetUserId(env, info);
    if (!userId) {
        IAM_LOGE("GetUserId fail");
        return nullptr;
    }

    std::unique_ptr<NapiStatusMonitor> statusMonitor = std::make_unique<NapiStatusMonitor>(*userId);
    if (statusMonitor == nullptr) {
        IAM_LOGE("statusMonitor is nullptr");
        return nullptr;
    }

    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr));
    NAPI_CALL(env,
        napi_wrap(
            env, thisVar, statusMonitor.get(),
            [](napi_env env, void *data, void *hint) {
                NapiStatusMonitor *statusMonitor = static_cast<NapiStatusMonitor *>(data);
                if (statusMonitor != nullptr) {
                    delete statusMonitor;
                }
            },
            nullptr, nullptr));
    statusMonitor.release();
    return thisVar;
}

napi_value StatusMonitorClass(napi_env env)
{
    napi_value result = nullptr;
    napi_property_descriptor classFuncsDescriptor[] = {
        DECLARE_NAPI_FUNCTION("getTemplateStatus", CompanionDeviceAuth::GetTemplateStatus),
        DECLARE_NAPI_FUNCTION("onTemplateChange", CompanionDeviceAuth::OnTemplateChange),
        DECLARE_NAPI_FUNCTION("offTemplateChange", CompanionDeviceAuth::OffTemplateChange),
        DECLARE_NAPI_FUNCTION("onContinuousAuthChange", CompanionDeviceAuth::OnContinuousAuthChange),
        DECLARE_NAPI_FUNCTION("offContinuousAuthChange", CompanionDeviceAuth::OffContinuousAuthChange),
        DECLARE_NAPI_FUNCTION("onAvailableDeviceChange", CompanionDeviceAuth::OnAvailableDeviceChange),
        DECLARE_NAPI_FUNCTION("offAvailableDeviceChange", CompanionDeviceAuth::OffAvailableDeviceChange),
    };
    NAPI_CALL(env,
        napi_define_class(env, "StatusMonitor", NAPI_AUTO_LENGTH, StatusMonitorConstructor, nullptr,
            sizeof(classFuncsDescriptor) / sizeof(napi_property_descriptor), classFuncsDescriptor, &result));
    return result;
}

int32_t GetStatusMonitorInternal(napi_env env, napi_callback_info info, napi_value &result)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    auto userId = GetUserId(env, info);
    ENSURE_OR_RETURN_VAL(userId, GENERAL_ERROR);
    int32_t ret = NapiStatusMonitor::CheckUserId(*userId);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckUserId fail, ret:%{public}d", ret);
        return ret;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(status == napi_ok && argc == ARGS_ONE, GENERAL_ERROR);
    napi_value napiStatusMonitor;
    status = napi_new_instance(env, StatusMonitorClass(env), argc, argv, &napiStatusMonitor);
    ENSURE_OR_RETURN_VAL(status == napi_ok, GENERAL_ERROR);
    result = napiStatusMonitor;
    return SUCCESS;
}

napi_value GetStatusMonitor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value result = nullptr;
    int32_t ret = GetStatusMonitorInternal(env, info, result);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return result;
}

int32_t RegisterDeviceSelectCallbackInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(status == napi_ok && argc == ARGS_ONE, GENERAL_ERROR);

    auto deviceSelectCallback = std::make_shared<NapiDeviceSelectCallback>(env);
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, GENERAL_ERROR);

    napi_ref ref = nullptr;
    status = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, argv[PARAM0], ref);
    ENSURE_OR_RETURN_VAL(status == napi_ok && ref != nullptr, GENERAL_ERROR);

    auto callbackRef = std::make_shared<JsRefHolder>(env, ref);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        CompanionDeviceAuthNapiHelper::DeleteReference(env, ref);
        return GENERAL_ERROR;
    }

    deviceSelectCallback->SetCallback(callbackRef);
    int32_t ret = CompanionDeviceAuthClient::GetInstance().RegisterDeviceSelectCallback(deviceSelectCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

int32_t RegisterPasscodePromptCallbackInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(status == napi_ok && argc == ARGS_ONE, GENERAL_ERROR);

    auto passcodePromptCallback = std::make_shared<NapiPasscodePromptCallback>(env);
    ENSURE_OR_RETURN_VAL(passcodePromptCallback != nullptr, GENERAL_ERROR);

    napi_ref ref = nullptr;
    status = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, argv[PARAM0], ref);
    ENSURE_OR_RETURN_VAL(status == napi_ok && ref != nullptr, GENERAL_ERROR);

    auto callbackRef = std::make_shared<JsRefHolder>(env, ref);
    if (callbackRef == nullptr || !callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        CompanionDeviceAuthNapiHelper::DeleteReference(env, ref);
        return GENERAL_ERROR;
    }

    passcodePromptCallback->SetCallback(callbackRef);
    int32_t ret = CompanionDeviceAuthClient::GetInstance().RegisterPasscodePromptCallback(passcodePromptCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("RegisterPasscodePromptCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value RegisterPasscodePromptCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = RegisterPasscodePromptCallbackInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t UnregisterPasscodePromptCallbackInternal()
{
    int32_t checkPermission = CheckPermission(ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    int32_t ret = CompanionDeviceAuthClient::GetInstance().UnregisterPasscodePromptCallback();
    if (ret != SUCCESS) {
        IAM_LOGE("UnregisterPasscodePromptCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value UnregisterPasscodePromptCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = UnregisterPasscodePromptCallbackInternal();
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value RegisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = RegisterDeviceSelectCallbackInternal(env, info);
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t UnregisterDeviceSelectCallbackInternal()
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);
    int32_t ret = CompanionDeviceAuthClient::GetInstance().UnregisterDeviceSelectCallback();
    if (ret != SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value UnregisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = UnregisterDeviceSelectCallbackInternal();
    if (ret != SUCCESS) {
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

int32_t UpdateEnabledBusinessIdsInternal(napi_env env, napi_callback_info info)
{
    int32_t checkPermission = CheckPermission(USE_USER_IDM_PERMISSION);
    ENSURE_OR_RETURN_VAL(checkPermission == SUCCESS, checkPermission);

    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(status == napi_ok && argc == ARGS_TWO, GENERAL_ERROR);

    std::vector<uint8_t> templateIdArray = {};
    status = CompanionDeviceAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], templateIdArray);
    ENSURE_OR_RETURN_VAL(status == napi_ok, GENERAL_ERROR);
    ENSURE_OR_RETURN_VAL(templateIdArray.size() >= sizeof(uint64_t), GENERAL_ERROR);
    uint64_t templateId {};
    if (memcpy_s(&templateId, sizeof(templateId), templateIdArray.data(), sizeof(uint64_t)) != EOK) {
        IAM_LOGE("memcpy_s failed for templateId");
        return GENERAL_ERROR;
    }

    std::vector<int32_t> enabledBusinessIds = {};
    status = CompanionDeviceAuthNapiHelper::GetInt32Array(env, argv[PARAM1], enabledBusinessIds);
    ENSURE_OR_RETURN_VAL(status == napi_ok, GENERAL_ERROR);

    int32_t ret =
        CompanionDeviceAuthClient::GetInstance().UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds);
    if (ret != SUCCESS) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_value UpdateEnabledBusinessIds(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value voidPromise = nullptr;
    napi_deferred promiseDeferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &voidPromise));
    if (promiseDeferred == nullptr || voidPromise == nullptr) {
        IAM_LOGE("fail to create promise object");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    int32_t ret = UpdateEnabledBusinessIdsInternal(env, info);
    if (ret != SUCCESS) {
        napi_reject_deferred(env, promiseDeferred, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return voidPromise;
    }

    napi_value returnVoid = nullptr;
    DoPromise(env, promiseDeferred, returnVoid, ret);
    IAM_LOGI("success");
    return voidPromise;
}

napi_value BusinessIdConstructor(napi_env env)
{
    napi_value businessId = nullptr;
    napi_value defaultId = nullptr;
    napi_value vendorBegin = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessId));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(BusinessId::DEFAULT), &defaultId));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(BusinessId::VENDOR_BEGIN), &vendorBegin));
    NAPI_CALL(env, napi_set_named_property(env, businessId, "DEFAULT", defaultId));
    NAPI_CALL(env, napi_set_named_property(env, businessId, "VENDOR_BEGIN", vendorBegin));
    return businessId;
}

napi_value DeviceIdTypeConstructor(napi_env env)
{
    napi_value deviceIdType = nullptr;
    napi_value unifiedDeviceId = nullptr;
    napi_value vendorBegin = nullptr;
    NAPI_CALL(env, napi_create_object(env, &deviceIdType));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DeviceIdType::UNIFIED_DEVICE_ID), &unifiedDeviceId));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DeviceIdType::VENDOR_BEGIN), &vendorBegin));
    NAPI_CALL(env, napi_set_named_property(env, deviceIdType, "UNIFIED_DEVICE_ID", unifiedDeviceId));
    NAPI_CALL(env, napi_set_named_property(env, deviceIdType, "VENDOR_BEGIN", vendorBegin));
    return deviceIdType;
}

napi_value SelectPurposeConstructor(napi_env env)
{
    napi_value selectPurpose = nullptr;
    napi_value selectAddDevice = nullptr;
    napi_value selectAuthDevice = nullptr;
    napi_value vendorBegin = nullptr;
    NAPI_CALL(env, napi_create_object(env, &selectPurpose));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(SelectPurpose::SELECT_ADD_DEVICE), &selectAddDevice));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(SelectPurpose::SELECT_AUTH_DEVICE), &selectAuthDevice));
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(SelectPurpose::VENDOR_BEGIN), &vendorBegin));
    NAPI_CALL(env, napi_set_named_property(env, selectPurpose, "SELECT_ADD_DEVICE", selectAddDevice));
    NAPI_CALL(env, napi_set_named_property(env, selectPurpose, "SELECT_AUTH_DEVICE", selectAuthDevice));
    NAPI_CALL(env, napi_set_named_property(env, selectPurpose, "VENDOR_BEGIN", vendorBegin));
    return selectPurpose;
}

napi_value CompanionDeviceAuthInit(napi_env env, napi_value exports)
{
    IAM_LOGI("start");
    napi_status status = napi_generic_failure;
    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_FUNCTION("getStatusMonitor", CompanionDeviceAuth::GetStatusMonitor),
        DECLARE_NAPI_FUNCTION("registerDeviceSelectCallback", CompanionDeviceAuth::RegisterDeviceSelectCallback),
        DECLARE_NAPI_FUNCTION("unregisterDeviceSelectCallback", CompanionDeviceAuth::UnregisterDeviceSelectCallback),
        DECLARE_NAPI_FUNCTION("updateEnabledBusinessIds", CompanionDeviceAuth::UpdateEnabledBusinessIds),
        DECLARE_NAPI_FUNCTION("registerPasscodePromptCallback", CompanionDeviceAuth::RegisterPasscodePromptCallback),
        DECLARE_NAPI_FUNCTION("unregisterPasscodePromptCallback",
            CompanionDeviceAuth::UnregisterPasscodePromptCallback),
    };
    status = napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(napi_property_descriptor), exportFuncs);
    if (status != napi_ok) {
        IAM_LOGE("napi_define_properties failed");
        NAPI_CALL(env, status);
    }
    return exports;
}

napi_value EnumExport(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_PROPERTY("BusinessId", BusinessIdConstructor(env)),
        DECLARE_NAPI_PROPERTY("DeviceIdType", DeviceIdTypeConstructor(env)),
        DECLARE_NAPI_PROPERTY("SelectPurpose", SelectPurposeConstructor(env)),
    };
    NAPI_CALL(env,
        napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors));
    return exports;
}

napi_value ModuleInit(napi_env env, napi_value exports)
{
    napi_value val = CompanionDeviceAuthInit(env, exports);
    return EnumExport(env, val);
}
} // namespace

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module module = { .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = ModuleInit,
        .nm_modname = "userIAM.companionDeviceAuth",
        .nm_priv = nullptr,
        .reserved = {} };
    napi_module_register(&module);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS