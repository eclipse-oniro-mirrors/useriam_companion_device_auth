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

#ifndef COMPANION_DEVICE_AUTH_CLIENT_H
#define COMPANION_DEVICE_AUTH_CLIENT_H

#include <functional>
#include <vector>

#include "companion_device_auth_types.h"
#include "icompanion_device_auth.h"
#include "iipc_available_device_status_callback.h"
#include "iipc_continuous_auth_status_callback.h"
#include "iipc_device_select_callback.h"
#include "iipc_template_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using CompanionDeviceAuthOnRemoteDiedCallback = std::function<void()>;

class CompanionDeviceAuthClient {
public:
    static CompanionDeviceAuthClient &GetInstance();

    virtual int32_t SubscribeAvailableDeviceStatus(const IpcSubscribeStatusParam &param,
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback) = 0;
    virtual int32_t UnsubscribeAvailableDeviceStatus(
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback) = 0;
    virtual int32_t SubscribeTemplateStatus(const IpcSubscribeStatusParam &param,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback) = 0;
    virtual int32_t UnsubscribeTemplateStatus(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback) = 0;
    virtual int32_t SubscribeContinuousAuthStatus(const IpcSubscribeContinuousAuthStatusParam &param,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback) = 0;
    virtual int32_t UnsubscribeContinuousAuthStatus(
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback) = 0;
    virtual int32_t UpdateTemplateEnabledBusinessIds(uint64_t templateId,
        const std::vector<int32_t> &enabledBusinessIds) = 0;
    virtual int32_t GetTemplateStatus(const IpcSubscribeStatusParam &param,
        std::vector<IpcTemplateStatus> &templateStatusArray) = 0;
    virtual int32_t RegisterDeviceSelectCallback(const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback) = 0;
    virtual int32_t UnregisterDeviceSelectCallback(const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback) = 0;
    virtual void SetOnRemoteDiedCallback(CompanionDeviceAuthOnRemoteDiedCallback &&onRemoteDiedCallback) = 0;

protected:
    virtual ~CompanionDeviceAuthClient() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CLIENT_H
