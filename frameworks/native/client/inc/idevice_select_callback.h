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

/**
 * @file device_select_callback.h
 *
 * @brief Device selection callback signature that returns appropriate devices for the requested purpose.
 * @since todo
 * @version todo
 */

#ifndef IDEVICE_SELECT_CALLBACK_H
#define IDEVICE_SELECT_CALLBACK_H

#include "companion_device_auth_common_defines.h"
#include "set_device_select_result_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IDeviceSelectCallback {
public:
    virtual ~IDeviceSelectCallback() = default;

    /**
     * @brief Device selection callback signature that returns appropriate devices for the requested purpose.
     *
     * @param selectPurpose Purpose value.
     * @param callback Set device select result callback.
     */
    virtual void OnDeviceSelect(int32_t selectPurpose,
        const std::shared_ptr<SetDeviceSelectResultCallback> &callback) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IDEVICE_SELECT_CALLBACK_H