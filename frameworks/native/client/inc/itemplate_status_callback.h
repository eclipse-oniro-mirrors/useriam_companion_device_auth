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
 * @file template_status_callback.h
 *
 * @brief Callback invoked when template statuses change.
 * @since todo
 * @version todo
 */

#ifndef ITEMPLATE_STATUS_CALLBACK_H
#define ITEMPLATE_STATUS_CALLBACK_H

#include "companion_device_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class ITemplateStatusCallback {
public:
    virtual ~ITemplateStatusCallback() = default;

    /**
     * @brief Callback invoked when template statuses change.
     *
     * @param templateStatusList Latest template status list.
     */
    virtual void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) = 0;

    /**
     * @brief Get user identifier for callback.
     *
     * @return user identifier.
     */
    virtual int32_t GetUserId() = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ITEMPLATE_STATUS_CALLBACK_H