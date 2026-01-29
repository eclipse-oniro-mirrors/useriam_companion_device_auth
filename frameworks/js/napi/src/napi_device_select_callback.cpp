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

#include "napi_device_select_callback.h"

#include "napi/native_node_api.h"
#include <uv.h>

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_device_auth_napi_helper.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
struct DeviceSelectCallbackHolder {
    std::shared_ptr<NapiDeviceSelectCallback> callback { nullptr };
    int32_t selectPurpose {};
    std::shared_ptr<SetDeviceSelectResultCallback> setCallback;
    napi_env env { nullptr };
};

void DeviceSelectCallback(std::shared_ptr<DeviceSelectCallbackHolder> deviceSelectCallbackHolder)
{
    IAM_LOGI("start");
    if (deviceSelectCallbackHolder == nullptr || deviceSelectCallbackHolder->callback == nullptr) {
        IAM_LOGE("deviceSelectCallbackHolder is invalid");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(deviceSelectCallbackHolder->env, &scope);
    if (scope == nullptr) {
        IAM_LOGE("scope is invalid");
        return;
    }

    ClientDeviceSelectResult result {};
    napi_value napiDeviceSelectResult = nullptr;
    ENSURE_OR_RETURN(deviceSelectCallbackHolder->callback != nullptr);
    napi_status status = deviceSelectCallbackHolder->callback->DoCallback(deviceSelectCallbackHolder->selectPurpose,
        &napiDeviceSelectResult);
    if (status != napi_ok) {
        IAM_LOGE("DoDeviceSelectCallback fail, ret:%{public}d", status);
        napi_close_handle_scope(deviceSelectCallbackHolder->env, scope);
        return;
    }

    status = CompanionDeviceAuthNapiHelper::ConvertNapiValueToClientDeviceSelectResult(deviceSelectCallbackHolder->env,
        napiDeviceSelectResult, result);
    if (status != napi_ok) {
        IAM_LOGE("ConvertNapiValueToClientDeviceSelectResult fail, ret:%{public}d", status);
        napi_close_handle_scope(deviceSelectCallbackHolder->env, scope);
        return;
    }
    if (deviceSelectCallbackHolder->setCallback == nullptr) {
        IAM_LOGE("setCallback is null");
        napi_close_handle_scope(deviceSelectCallbackHolder->env, scope);
        return;
    }
    deviceSelectCallbackHolder->setCallback->OnSetDeviceSelectResult(result);
    napi_close_handle_scope(deviceSelectCallbackHolder->env, scope);
    IAM_LOGI("end");
}
} // namespace

NapiDeviceSelectCallback::NapiDeviceSelectCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("NapiDeviceSelectCallback get null env");
    }
}

NapiDeviceSelectCallback::~NapiDeviceSelectCallback()
{
}

void NapiDeviceSelectCallback::SetCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callback_ = callback;
}

napi_status NapiDeviceSelectCallback::DoCallback(int32_t selectPurpose, napi_value *result)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback_ is null");
        return napi_ok;
    }

    napi_value napiSelectPurpose = nullptr;
    napi_status status = napi_create_int32(env_, selectPurpose, &napiSelectPurpose);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_int32 fail, ret:%{public}d", status);
        return status;
    }

    return CompanionDeviceAuthNapiHelper::CallNapiFuncWithResult(env_, callback_->Get(), ARGS_ONE, &napiSelectPurpose,
        result);
}

void NapiDeviceSelectCallback::OnDeviceSelect(int32_t selectPurpose,
    const std::shared_ptr<SetDeviceSelectResultCallback> &callback)
{
    IAM_LOGI("start, selectPurpose:%{public}d", selectPurpose);
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    std::shared_ptr<DeviceSelectCallbackHolder> deviceSelectCallbackHolder =
        std::make_shared<DeviceSelectCallbackHolder>();
    ENSURE_OR_RETURN(deviceSelectCallbackHolder != nullptr);
    deviceSelectCallbackHolder->callback = shared_from_this();
    deviceSelectCallbackHolder->selectPurpose = selectPurpose;
    deviceSelectCallbackHolder->setCallback = callback;
    deviceSelectCallbackHolder->env = env_;
    auto task = [deviceSelectCallbackHolder]() { DeviceSelectCallback(deviceSelectCallbackHolder); };
    // clang-format off
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "CompanionDeviceAuthNapi::NapiDeviceSelectCallback::OnDeviceSelect") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
    // clang-format on
    IAM_LOGI("end");
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS