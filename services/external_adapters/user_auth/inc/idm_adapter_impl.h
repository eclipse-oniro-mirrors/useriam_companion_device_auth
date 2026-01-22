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

#ifndef COMPANION_DEVICE_AUTH_IDM_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_IDM_ADAPTER_IMPL_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "user_idm_client_callback.h"

#include "idm_adapter.h"
#include "iremote_object.h"
#include "sa_status_listener.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class IdmAdapterImpl : public IIdmAdapter, public std::enable_shared_from_this<IdmAdapterImpl> {
public:
    static std::shared_ptr<IdmAdapterImpl> Create();
    ~IdmAdapterImpl() override;

    std::vector<uint64_t> GetUserTemplates(int32_t userId) override;
    std::unique_ptr<Subscription> SubscribeUserTemplateChange(int32_t userId, TemplateChangeCallback callback) override;
    void QueryAndUpdateCache(int32_t userId);

private:
    IdmAdapterImpl();
    bool Initialize();
    void OnUserIdmServiceReady();
    void OnUserIdmServiceUnavailable();
    void Unsubscribe(uint64_t subscriptionId);

    void NotifyTemplateChange(int32_t userId, const std::vector<uint64_t> &templateIds);

    std::map<int32_t, std::vector<uint64_t>> templateCache_;
    std::map<uint64_t, std::pair<int32_t, TemplateChangeCallback>> subscriptions_;
    std::unique_ptr<SaStatusListener> saListener_;
    std::shared_ptr<UserAuth::CredChangeEventListener> eventListener_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IDM_ADAPTER_IMPL_H
