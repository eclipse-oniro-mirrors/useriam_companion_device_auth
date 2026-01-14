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

#ifndef COMPANION_DEVICE_AUTH_CLIENT_IMPL_H
#define COMPANION_DEVICE_AUTH_CLIENT_IMPL_H

#include <mutex>
#include <optional>

#include "nocopyable.h"
#include "system_ability_listener.h"

#include "common_defines.h"
#include "companion_device_auth_client.h"
#include "companion_device_auth_common_defines.h"

#ifndef ENABLE_TEST
#include "ipc_client_fetcher.h"
#endif
#include "icompanion_device_auth.h"
#include "ipc_available_device_status_callback_service.h"
#include "ipc_continuous_auth_status_callback_service.h"
#include "ipc_device_select_callback_service.h"
#include "ipc_template_status_callback_service.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthClientImpl final : public CompanionDeviceAuthClient, NoCopyable {
public:
    int32_t RegisterDeviceSelectCallback(const std::shared_ptr<IDeviceSelectCallback> &callback) override;
    int32_t UnregisterDeviceSelectCallback() override;
    int32_t UpdateTemplateEnabledBusinessIds(const uint64_t templateId,
        const std::vector<int32_t> enabledBusinessIds) override;
    int32_t GetTemplateStatus(const int32_t localUserId,
        std::vector<ClientTemplateStatus> &templateStatusList) override;
    int32_t SubscribeTemplateStatusChange(const int32_t localUserId,
        const std::shared_ptr<ITemplateStatusCallback> &callback) override;
    int32_t UnsubscribeTemplateStatusChange(const std::shared_ptr<ITemplateStatusCallback> &callback) override;
    int32_t SubscribeContinuousAuthStatusChange(const int32_t localUserId,
        const std::shared_ptr<IContinuousAuthStatusCallback> &callback,
        const std::optional<uint64_t> templateId = std::nullopt) override;
    int32_t UnsubscribeContinuousAuthStatusChange(
        const std::shared_ptr<IContinuousAuthStatusCallback> &callback) override;
    int32_t SubscribeAvailableDeviceStatus(const int32_t localUserId,
        const std::shared_ptr<IAvailableDeviceStatusCallback> &callback) override;
    int32_t UnsubscribeAvailableDeviceStatus(const std::shared_ptr<IAvailableDeviceStatusCallback> &callback) override;
    int32_t CheckLocalUserIdValid(const int32_t localUserId, bool &isUserIdValid) override;
    void SubscribeCompanionDeviceAuthSaStatus();

#ifndef ENABLE_TEST
private:
#endif
    CompanionDeviceAuthClientImpl();
    ~CompanionDeviceAuthClientImpl() override;

#ifdef ENABLE_TEST
    void SetProxy(const sptr<ICompanionDeviceAuth> &proxy);
#endif

    void ReregisterDeviceSelectCallback();
    void ResubscribeTemplateStatusChange();
    void ResubscribeContinuousAuthStatusChange();
    void ResubscribeAvailableDeviceStatus();

    void ResetProxy(const wptr<IRemoteObject> &remote);
    sptr<ICompanionDeviceAuth> GetProxy();
    void PrintIpcTemplateStatus(const IpcTemplateStatus &ipcTemplateStatus);

    sptr<ICompanionDeviceAuth> proxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
    std::recursive_mutex mutex_;
    std::shared_ptr<IDeviceSelectCallback> deviceSelectCallback_ { nullptr };
    std::vector<sptr<IpcTemplateStatusCallbackService>> templateStatusCallbacks_;
    std::vector<sptr<IpcContinuousAuthStatusCallbackService>> continuousAuthStatusCallbacks_;
    std::vector<sptr<IpcAvailableDeviceStatusCallbackService>> availableDeviceStatusCallbacks_;
    sptr<SystemAbilityListener> companionDeviceAuthSaStatusListener_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_CLIENT_H