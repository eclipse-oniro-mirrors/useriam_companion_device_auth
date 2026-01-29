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

#include "companion_device_auth_napi_impl.h"

#include "napi_device_select_callback.h"
#include "securec.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "companion_device_auth_client.h"
#include "scope_guard.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
napi_value CompanionDeviceAuthNapiImpl::RegisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t errorCode = ResultCode::GENERAL_ERROR;
    ScopeGuard guard([&]() { napi_throw(env, CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, errorCode)); });

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return nullptr;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return nullptr;
    }

    auto deviceSelectCallback = std::make_shared<NapiDeviceSelectCallback>(env);
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, nullptr);

    auto callbackRef = std::make_shared<JsRefHolder>(env, argv[PARAM0]);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, nullptr);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return nullptr;
    }

    deviceSelectCallback->SetCallback(callbackRef);
    int32_t ret = CompanionDeviceAuthClient::GetInstance().RegisterDeviceSelectCallback(deviceSelectCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("RegisterDeviceSelectCallback fail, ret:%{public}d", ret);
        errorCode = ret;
        return nullptr;
    }

    guard.Cancel();
    IAM_LOGI("success");
    return nullptr;
}

napi_value CompanionDeviceAuthNapiImpl::UnregisterDeviceSelectCallback(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    int32_t ret = CompanionDeviceAuthClient::GetInstance().UnregisterDeviceSelectCallback();
    if (ret != SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback fail, ret:%{public}d", ret);
        napi_throw(env, CompanionDeviceAuth::CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ret));
        return nullptr;
    }
    IAM_LOGI("success");
    return nullptr;
}

napi_value CompanionDeviceAuthNapiImpl::UpdateEnabledBusinessIds(napi_env env, napi_callback_info info,
    napi_value voidPromise, napi_deferred promiseDeferred)
{
    IAM_LOGI("start");
    int32_t errorCode = ResultCode::GENERAL_ERROR;
    ScopeGuard guard([&]() {
        napi_reject_deferred(env, promiseDeferred,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, errorCode));
    });

    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    ENSURE_OR_RETURN_VAL(status == napi_ok, voidPromise);
    ENSURE_OR_RETURN_VAL(argc == ARGS_TWO, voidPromise);

    std::vector<uint8_t> templateIdArray = {};
    status = CompanionDeviceAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], templateIdArray);
    if (status != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail, ret:%{public}d", status);
        return voidPromise;
    }

    ENSURE_OR_RETURN_VAL(templateIdArray.size() >= sizeof(uint64_t), voidPromise);
    uint64_t templateId {};
    if (memcpy_s(&templateId, sizeof(templateId), templateIdArray.data(), sizeof(uint64_t)) != EOK) {
        IAM_LOGE("memcpy_s failed for templateId");
        return voidPromise;
    }

    std::vector<int32_t> enabledBusinessIds = {};
    status = CompanionDeviceAuthNapiHelper::GetInt32Array(env, argv[PARAM1], enabledBusinessIds);
    if (status != napi_ok) {
        IAM_LOGE("GetInt32Array fail, ret:%{public}d", status);
        return voidPromise;
    }

    int32_t ret =
        CompanionDeviceAuthClient::GetInstance().UpdateTemplateEnabledBusinessIds(templateId, enabledBusinessIds);
    if (ret != SUCCESS) {
        IAM_LOGE("UpdateTemplateEnabledBusinessIds fail, ret:%{public}d", ret);
        errorCode = ret;
        return voidPromise;
    }

    guard.Cancel();
    napi_value returnVoid = nullptr;
    DoPromise(env, promiseDeferred, returnVoid, ret);
    IAM_LOGI("success");
    return voidPromise;
}

void CompanionDeviceAuthNapiImpl::DoPromise(napi_env env, napi_deferred promise, napi_value promiseValue,
    int32_t result)
{
    IAM_LOGI("start");
    if (promise == nullptr) {
        napi_reject_deferred(env, promise,
            CompanionDeviceAuthNapiHelper::GenerateBusinessError(env, ResultCode::GENERAL_ERROR));
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
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS