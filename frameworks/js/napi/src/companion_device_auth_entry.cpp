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

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

#include "iam_logger.h"

#include "status_monitor.h"
#include "companion_device_auth_napi_impl.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using NapiStatusMonitor = StatusMonitor<JsRefHolder, JsRefHolder, JsRefHolder>;
using NapiTemplateStatusCallback = TemplateStatusCallbackWrapper<JsRefHolder>;
using NapiAvailableDeviceStatusCallback = AvailableDeviceStatusCallbackWrapper<JsRefHolder>;
using NapiContinuousAuthStatusCallback = ContinuousAuthStatusCallbackWrapper<JsRefHolder>;

namespace {
int32_t CheckPermission()
{
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOW_MASK;

    if (AccessTokenKit::VerifyAccessToken(tokenId, USE_USER_IDM_PERMISSION) != RET_SUCCESS) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
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
        return nullptr;
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
    if (promise == nullptr) {
        napi_reject_deferred(env, promise, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return;
    }

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

napi_value GetTemplateStatus(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value promiseValue = nullptr;
    napi_deferred promiseDeferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &promiseValue));

    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_reject_deferred(
            env, promiseDeferred, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return promiseValue;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return promiseValue;
    }

    std::vector<ClientTemplateStatus> clientTemplateStatusList;
    napi_value templateStatusList = nullptr;
    int32_t ret = statusMonitor->GetTemplateStatus(clientTemplateStatusList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
        napi_reject_deferred(env, promiseDeferred, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return promiseValue;
    } else {
        templateStatusList =
            CompanionDeviceAuthNapiHelper::ConvertTemplateStatusListToNapiValue(env, clientTemplateStatusList);
        if (templateStatusList == nullptr) {
            IAM_LOGE("TemplateStatusListToNapiValue fail");
            ret = GENERAL_ERROR;
        }
    }
    DoPromise(env, promiseDeferred, templateStatusList, ret);
    IAM_LOGI("success");
    return promiseValue;
}

napi_value OnTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    auto callback = GetCallbackRef(env, info);
    if (!callback) {
        IAM_LOGE("GetCallbackRef fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret =
        statusMonitor->OnTemplateChange(std::make_shared<NapiTemplateStatusCallback>(JsRefHolder(env, *callback)));
    if (ret != SUCCESS) {
        IAM_LOGE("OnTemplateChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OffTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    auto callback = GetCallbackRef(env, info);
    if (!callback) {
        IAM_LOGE("GetCallbackRef fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    std::shared_ptr<NapiTemplateStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiTemplateStatusCallback>(JsRefHolder(env, *callback));
    }
    int32_t ret = statusMonitor->OffTemplateChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffTemplateChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OnAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    auto callback = GetCallbackRef(env, info);
    if (!callback) {
        IAM_LOGE("GetCallbackRef fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    
    int32_t ret = statusMonitor->OnAvailableDeviceChange(
        std::make_shared<NapiAvailableDeviceStatusCallback>(JsRefHolder(env, *callback)));
    if (ret != SUCCESS) {
        IAM_LOGE("OnAvailableDeviceChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OffAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    auto callback = GetCallbackRef(env, info);
    if (!callback) {
        IAM_LOGE("GetCallbackRef fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    std::shared_ptr<NapiAvailableDeviceStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiAvailableDeviceStatusCallback>(JsRefHolder(env, *callback));
    }
    int32_t ret = statusMonitor->OffAvailableDeviceChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffAvailableDeviceChange fail:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

bool GetOnContinuousAuthChangeParam(napi_env env, napi_callback_info info,
    std::optional<uint64_t> &templateIdOpt, std::shared_ptr<NapiContinuousAuthStatusCallback> &callback)
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

    bool hasTemplateId = false;
    status = napi_has_named_property(env, argv[PARAM0], "templateId", &hasTemplateId);
    if (status != napi_ok) {
        IAM_LOGE("fail to check templateId property");
        return false;
    }

    if (!hasTemplateId) {
        IAM_LOGI("templateId not provided in ContinuousAuthParam");
    } else {
        napi_value templateIdProperty = nullptr;
        status = napi_get_named_property(env, argv[PARAM0], "templateId", &templateIdProperty);
        if (status != napi_ok) {
            IAM_LOGE("fail to get templateId property");
            return false;
        }
        uint64_t templateIdVal {};
        napi_status status =
            CompanionDeviceAuthNapiHelper::ConvertNapiUint8ArrayToUint64(env, templateIdProperty, templateIdVal);
        if (status != napi_ok) {
            IAM_LOGE("ConvertNapiUint8ArrayToUint64 fail, ret:%{public}d", status);
            return false;
        }
        templateIdOpt = templateIdVal;
    }

    napi_ref ref = nullptr;
    status = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, argv[PARAM1], ref);
    if (status != napi_ok || ref == nullptr) {
        IAM_LOGE("GetFunctionRef fail %{public}d", status);
        return false;
    }
    callback = std::make_shared<NapiContinuousAuthStatusCallback>(JsRefHolder(env, ref));
    return true;
}

napi_value OnContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    std::optional<uint64_t> templateIdOpt;
    std::shared_ptr<NapiContinuousAuthStatusCallback> callback;
    if (!GetOnContinuousAuthChangeParam(env, info, templateIdOpt, callback)) {
        IAM_LOGE("GetOnContinuousAuthChangeParam fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    int32_t ret = statusMonitor->OnContinuousAuthChange(templateIdOpt, callback);
    if (ret != SUCCESS) {
        IAM_LOGE("OnContinuousAuthChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OffContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    NapiStatusMonitor *statusMonitor = nullptr;
    if (!UnwrapStatusMonitor(env, info, &statusMonitor)) {
        IAM_LOGE("UnwrapStatusMonitor fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    auto callback = GetCallbackRef(env, info);
    if (!callback) {
        IAM_LOGE("GetCallbackRef fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    std::shared_ptr<NapiContinuousAuthStatusCallback> callbackWrapper = nullptr;
    if (*callback != nullptr) {
        callbackWrapper = std::make_shared<NapiContinuousAuthStatusCallback>(JsRefHolder(env, *callback));
    }

    int32_t ret = statusMonitor->OffContinuousAuthChange(callbackWrapper);
    if (ret != SUCCESS) {
        IAM_LOGE("OffContinuousAuthChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
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

napi_value GetStatusMonitor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    auto userId = GetUserId(env, info);
    if (!userId) {
        IAM_LOGE("GetUserId fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = NapiStatusMonitor::CheckUserId(*userId);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckUserId fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok || argc != ARGS_ONE) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d argc:%{public}zu", status, argc);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    napi_value napiStatusMonitor;
    status = napi_new_instance(env, StatusMonitorClass(env), argc, argv, &napiStatusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("napi_new_instance fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    IAM_LOGI("success");
    return napiStatusMonitor;
}

napi_value RegisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    return CompanionDeviceAuthNapiImpl::RegisterDeviceSelectCallback(env, info);
}

napi_value UnregisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return nullptr;
    }

    return CompanionDeviceAuthNapiImpl::UnregisterDeviceSelectCallback(env, info);
}

napi_value UpdateEnabledBusinessIds(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value voidPromise = nullptr;
    napi_deferred promiseDeferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &promiseDeferred, &voidPromise));

    int32_t checkPermission = CheckPermission();
    if (checkPermission != SUCCESS) {
        IAM_LOGE("CheckPermission fail, ret:%{public}d", checkPermission);
        napi_reject_deferred(
            env, promiseDeferred, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, checkPermission));
        return voidPromise;
    }

    return CompanionDeviceAuthNapiImpl::UpdateEnabledBusinessIds(env, info, voidPromise, promiseDeferred);
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