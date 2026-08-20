/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SYNCED_PEER_REGISTRY_H
#define SYNCED_PEER_REGISTRY_H

#include <cstdint>
#include <map>
#include <memory>

#include "nocopyable.h"

#include "cross_device_common.h"
#include "event_bus/event_bus.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SyncedPeerRegistry : public NoCopyable {
public:
    SyncedPeerRegistry() = default;
    ~SyncedPeerRegistry() = default;

    bool Start();
    bool IsRecentlySynced(const PhysicalDeviceKey &deviceKey) const;

private:
    void HandlePeerSynced(const EventData &data);
    void RecordPeerSync(const PhysicalDeviceKey &deviceKey);

    std::map<PhysicalDeviceKey, SteadyTimeMs> syncedPeers_;
    std::shared_ptr<Subscription> peerSyncSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SYNCED_PEER_REGISTRY_H
