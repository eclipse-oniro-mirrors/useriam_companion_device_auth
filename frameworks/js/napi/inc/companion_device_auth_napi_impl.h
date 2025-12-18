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

#ifndef COMPANION_DEVICE_AUTH_NAPI_IMPL_H
#define COMPANION_DEVICE_AUTH_NAPI_IMPL_H

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"
#include "companion_device_auth_napi_common.h"
#include "companion_device_auth_napi_helper.h"
#include "idevice_select_callback.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthNapiImpl {
public:
    static napi_value RegisterDeviceSelectCallback(napi_env env, napi_callback_info info);
    static napi_value UnregisterDeviceSelectCallback(napi_env env, napi_callback_info info);
    static napi_value UpdateEnabledBusinessIds(napi_env env, napi_callback_info info);

private:
    CompanionDeviceAuthNapiImpl() = default;
    ~CompanionDeviceAuthNapiImpl() = default;

    static void DoPromise(napi_env env, napi_deferred promise, napi_value promiseValue, int32_t result);
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_NAPI_IMPL_H