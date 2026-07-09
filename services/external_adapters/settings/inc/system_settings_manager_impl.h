/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_IMPL_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common_event_subscriber.h"
#include "data_ability_observer_stub.h"
#include "datashare_helper.h"
#include "iremote_object.h"
#include "refbase.h"
#include "sa_status_listener.h"
#include "service_common.h"
#include "subscription.h"
#include "system_ability_definition.h"
#include "system_settings_manager.h"
#include "uri.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

struct SettingMeta {
    SettingKey key;
    const char *dataShareKey;
    bool perUser;
};

class SystemSettingsManagerImpl final : public std::enable_shared_from_this<SystemSettingsManagerImpl>,
                                        public ISystemSettingsManager {
public:
    static std::shared_ptr<SystemSettingsManagerImpl> Create(const wptr<IRemoteObject> &cdaService);

    ~SystemSettingsManagerImpl() override;

    std::string GetSettingsValue(SettingKey settingKey) override;
    std::unique_ptr<Subscription> SubscribeSettingsChange(SettingKey settingKey,
        SettingsChangeCallback &&callback) override;

private:
    explicit SystemSettingsManagerImpl(const wptr<IRemoteObject> &cdaService);

    bool Initialize();

    class ObserverStub final : public AAFwk::DataAbilityObserverStub {
    public:
        ObserverStub(SettingKey key, std::weak_ptr<SystemSettingsManagerImpl> manager)
            : key_(key),
              manager_(std::move(manager))
        {
        }
        ~ObserverStub() override = default;
        void OnChange() override;

    private:
        SettingKey key_;
        std::weak_ptr<SystemSettingsManagerImpl> manager_;
    };

    class DataShareReadySubscriber final : public EventFwk::CommonEventSubscriber {
    public:
        DataShareReadySubscriber(const EventFwk::CommonEventSubscribeInfo &info,
            std::weak_ptr<SystemSettingsManagerImpl> manager)
            : EventFwk::CommonEventSubscriber(info),
              manager_(std::move(manager))
        {
        }
        ~DataShareReadySubscriber() override = default;
        void OnReceiveEvent(const EventFwk::CommonEventData &data) override;

    private:
        std::weak_ptr<SystemSettingsManagerImpl> manager_;
    };

    struct SettingState {
        SettingKey key;
        std::string dataShareKey;
        bool perUser { false };
        std::optional<int32_t> userId;
        sptr<ObserverStub> observer;
        bool observerRegistered { false };
        std::string cachedValue;
        std::map<uint64_t, SettingsChangeCallback> subscribers;
    };

    SettingState *FindState(SettingKey key);

    void OnCommonEventServiceReady();
    void OnCommonEventServiceRemoved();
    void OnDataShareReady();
    void OnActiveUserChanged(std::optional<int32_t> newUserId);
    void EnsureObservers();
    void RefreshCache(SettingState &state);
    void NotifyAll();
    void NotifySubscribers(SettingState &state);
    void OnSettingChanged(SettingKey key);
    void Unsubscribe(SettingKey key, uint64_t subId);

    Uri BuildKeyUri(std::optional<int32_t> userId, const std::string &key) const;
    std::string QuerySettingsString(DataShare::DataShareHelper &helper, std::optional<int32_t> userId,
        const std::string &key) const;
    std::string QueryValue(std::optional<int32_t> userId, const std::string &key);
    bool RegisterOneObserver(SettingState &state);
    void UnregisterOneObserver(SettingState &state);

    wptr<IRemoteObject> cdaService_;
    std::optional<int32_t> currentActiveUser_;
    std::vector<SettingState> states_;
    std::unique_ptr<Subscription> activeUserIdSubscription_;
    std::unique_ptr<SaStatusListener> cesStatusListener_;
    std::shared_ptr<DataShareReadySubscriber> dataShareReadySubscriber_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_IMPL_H
