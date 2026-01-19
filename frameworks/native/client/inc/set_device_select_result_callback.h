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

#ifndef SET_DEVICE_SELECT_RESULT_CALLBACK_H
#define SET_DEVICE_SELECT_RESULT_CALLBACK_H

#include <mutex>

#include "companion_device_auth_common_defines.h"
#include "companion_device_auth_types.h"
#include "iipc_set_device_select_result_callback.h"
#include "ipc_device_select_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SetDeviceSelectResultCallback {
public:
    explicit SetDeviceSelectResultCallback(const sptr<IIpcSetDeviceSelectResultCallback> &callback);
    ~SetDeviceSelectResultCallback() = default;
    int32_t OnSetDeviceSelectResult(const ClientDeviceSelectResult &result);

private:
    sptr<IIpcSetDeviceSelectResultCallback> callback_ { nullptr };
    std::recursive_mutex mutex_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // SET_DEVICE_SELECT_RESULT_CALLBACK_H