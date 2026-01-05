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

#ifndef NAPI_DEVICE_SELECT_CALLBACK_H
#define NAPI_DEVICE_SELECT_CALLBACK_H

#include <mutex>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_napi_helper.h"
#include "companion_device_auth_types.h"
#include "idevice_select_callback.h"
#include "set_device_select_result_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class NapiDeviceSelectCallback : public IDeviceSelectCallback,
                                 public std::enable_shared_from_this<NapiDeviceSelectCallback>,
                                 public NoCopyable {
public:
    explicit NapiDeviceSelectCallback(napi_env env);
    ~NapiDeviceSelectCallback() override;

    void OnDeviceSelect(int32_t selectPurpose, const std::shared_ptr<SetDeviceSelectResultCallback> &callback) override;

    napi_status DoCallback(int32_t selectPurpose, napi_value *result);
    void SetCallback(const std::shared_ptr<JsRefHolder> &callback_);

private:
    napi_env env_ = nullptr;
    std::recursive_mutex mutex_;
    std::shared_ptr<JsRefHolder> callback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // NapiDeviceSelectCallback