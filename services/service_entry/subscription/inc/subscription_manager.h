/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H
#define COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "iremote_object.h"
#include "nocopyable.h"

#include "access_token_kit.h"
#include "app_foreground_state_adapter.h"
#include "available_device_subscription.h"
#include "companion_device_auth_types.h"
#include "continuous_auth_subscription.h"
#include "iipc_available_device_status_callback.h"
#include "iipc_continuous_auth_status_callback.h"
#include "iipc_template_status_callback.h"
#include "stale_subscription_monitor.h"
#include "subscription.h"
#include "template_status_subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SubscriptionManager : public std::enable_shared_from_this<SubscriptionManager>, public NoCopyable {
public:
    static std::shared_ptr<SubscriptionManager> Create();
    ~SubscriptionManager() = default;

    ResultCode AddAvailableDeviceStatusCallback(int32_t userId, CallerInfo callerInfo,
        const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback);
    void RemoveAvailableDeviceStatusCallback(
        const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback);
    ResultCode AddTemplateStatusCallback(int32_t userId, CallerInfo callerInfo,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    void RemoveTemplateStatusCallback(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    ResultCode AddContinuousAuthStatusCallback(int32_t userId, std::optional<uint64_t> templateId,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    void RemoveContinuousAuthStatusCallback(const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);

private:
    SubscriptionManager() = default;

    bool Init();

    class CallerSubscription {
    public:
        CallerSubscription(const CallerInfo &callerInfo, std::weak_ptr<StaleSubscriptionMonitor> monitor);

    private:
        CallerTokenType callerType_ { CallerTokenType::Hap };
        std::unique_ptr<Subscription> staleMonitorSub_;
        std::unique_ptr<Subscription> bundleSub_;
    };

    void UpdateSubscribeMode();
    void EnsureAppForegroundStateSubscribed();

    std::shared_ptr<AvailableDeviceSubscription> GetOrCreateAvailableDeviceSubscription(UserId userId);
    std::shared_ptr<TemplateStatusSubscription> GetOrCreateTemplateStatusSubscription(UserId userId);
    std::shared_ptr<ContinuousAuthSubscription> GetOrCreateContinuousAuthSubscription(UserId userId,
        std::optional<TemplateId> templateId);

    std::map<UserId, std::shared_ptr<AvailableDeviceSubscription>> availableDeviceSubscriptions_;
    std::map<UserId, std::shared_ptr<TemplateStatusSubscription>> templateStatusSubscriptions_;
    std::map<std::pair<UserId, std::optional<TemplateId>>, std::shared_ptr<ContinuousAuthSubscription>>
        continuousAuthSubscriptions_;

    std::map<sptr<IRemoteObject>, CallerSubscription> callerSubs_;
    std::unique_ptr<Subscription> foregroundAppSub_;
    std::shared_ptr<StaleSubscriptionMonitor> staleSubscriptionMonitor_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SUBSCRIPTION_MANAGER_H
