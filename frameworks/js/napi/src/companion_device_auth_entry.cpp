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
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_napi_impl.h"
#include "status_monitor.h"
#include "tokenid_kit.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
bool CheckUseUserIdmPermission()
{
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOW_MASK;
    if (AccessTokenKit::VerifyAccessToken(tokenId, USE_USER_IDM_PERMISSION) != RET_SUCCESS) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        return false;
    }
    return true;
}

bool CheckCallerIsSystemApp()
{
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    AccessTokenID tokenId = fullTokenId & TOKEN_ID_LOW_MASK;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (!checkRet || callingType != Security::AccessToken::TOKEN_HAP) {
        IAM_LOGE("the caller is not system application");
        return false;
    }
    IAM_LOGI("the caller is system application");
    return true;
}

napi_status UnwrapStatusMonitor(napi_env env, napi_callback_info info, StatusMonitor **statusMonitor)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { nullptr };
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return ret;
    }
    ret = napi_unwrap(env, thisVar, reinterpret_cast<void **>(statusMonitor));
    if (ret != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        return ret;
    }
    if (*statusMonitor == nullptr) {
        IAM_LOGE("statusMonitor is null");
        return napi_generic_failure;
    }
    return ret;
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return promiseValue;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_SYSTEM_PERMISSION_FAILED));
        return promiseValue;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    int32_t ret = statusMonitor->OnTemplateChange(env, info);
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = statusMonitor->OffTemplateChange(env, info);
    if (ret != SUCCESS) {
        IAM_LOGE("OffTemplateChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OnContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = statusMonitor->OnContinuousAuthChange(env, info);
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = statusMonitor->OffContinuousAuthChange(env, info);
    if (ret != SUCCESS) {
        IAM_LOGE("OffContinuousAuthChange fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value OnAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = statusMonitor->OnAvailableDeviceChange(env, info);
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    StatusMonitor *statusMonitor = nullptr;
    napi_status status = UnwrapStatusMonitor(env, info, &statusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("UnwrapStatusMonitor fail:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }
    int32_t ret = statusMonitor->OffAvailableDeviceChange(env, info);
    if (ret != SUCCESS) {
        IAM_LOGE("OffAvailableDeviceChange fail:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value StatusMonitorConstructor(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::unique_ptr<StatusMonitor> statusMonitor { new (std::nothrow) StatusMonitor(env) };
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
                StatusMonitor *statusMonitor = static_cast<StatusMonitor *>(data);
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
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    napi_value napiStatusMonitor;
    napi_status status = napi_new_instance(env, StatusMonitorClass(env), 0, nullptr, &napiStatusMonitor);
    if (status != napi_ok) {
        IAM_LOGE("napi_new_instance fail, ret:%{public}d", status);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    StatusMonitor *statusMonitor;
    status = napi_unwrap(env, napiStatusMonitor, reinterpret_cast<void **>(&statusMonitor));
    if (status != napi_ok) {
        IAM_LOGE("napi_unwrap fail");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    if (statusMonitor == nullptr) {
        IAM_LOGE("statusMonitor is null");
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, GENERAL_ERROR));
        return nullptr;
    }

    int32_t ret = statusMonitor->SetLocalUserId(env, info);
    if (ret != SUCCESS) {
        IAM_LOGE("SetLocalUserId fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }

    IAM_LOGI("success");
    return napiStatusMonitor;
}

napi_value RegisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
        return nullptr;
    }

    return CompanionDeviceAuthNapiImpl::RegisterDeviceSelectCallback(env, info);
}

napi_value UnregisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return nullptr;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_throw(env,
            CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env,
                CHECK_SYSTEM_PERMISSION_FAILED));
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

    if (!CheckUseUserIdmPermission()) {
        IAM_LOGE("CheckUseUserIdmPermission fail");
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_PERMISSION_FAILED));
        return voidPromise;
    }

    if (!CheckCallerIsSystemApp()) {
        IAM_LOGE("CheckCallerIsSystemApp fail");
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, CHECK_SYSTEM_PERMISSION_FAILED));
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