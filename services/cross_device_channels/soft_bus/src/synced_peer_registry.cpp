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

#include "synced_peer_registry.h"

#include <algorithm>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "cda_attributes.h"
#include "common_defines.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SYNCED_PEER_REGISTRY

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr size_t MAX_SYNCED_PEERS = 50;
constexpr uint64_t SYNCED_PEER_TTL_MS = 7ULL * 24 * 60 * 60 * 1000;
} // namespace

bool SyncedPeerRegistry::Start()
{
    peerSyncSubscription_ =
        GetEventBus().Subscribe(EventType::PEER_SYNCED, [this](const EventData &data) { HandlePeerSynced(data); });
    ENSURE_OR_RETURN_VAL(peerSyncSubscription_ != nullptr, false);
    return true;
}

void SyncedPeerRegistry::HandlePeerSynced(const EventData &data)
{
    Attributes payload(data);
    std::string deviceId;
    int32_t idTypeValue = 0;
    if (!payload.GetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceId) ||
        !payload.GetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, idTypeValue)) {
        IAM_LOGE("failed to decode peer synced event");
        return;
    }

    PhysicalDeviceKey key {};
    key.idType = static_cast<DeviceIdType>(idTypeValue);
    key.deviceId = deviceId;
    RecordPeerSync(key);
}

void SyncedPeerRegistry::RecordPeerSync(const PhysicalDeviceKey &deviceKey)
{
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(now.has_value());

    auto it = syncedPeers_.find(deviceKey);
    if (it != syncedPeers_.end()) {
        it->second = now.value();
        return;
    }

    if (syncedPeers_.size() >= MAX_SYNCED_PEERS) {
        auto oldest = std::min_element(syncedPeers_.begin(), syncedPeers_.end(),
            [](const auto &a, const auto &b) { return a.second < b.second; });
        IAM_LOGW("synced peer list full, evict oldest device %{public}s", GET_MASKED_STR_CSTR(oldest->first.deviceId));
        syncedPeers_.erase(oldest);
    }

    syncedPeers_[deviceKey] = now.value();
    IAM_LOGI("record synced peer %{public}s", GET_MASKED_STR_CSTR(deviceKey.deviceId));
}

bool SyncedPeerRegistry::IsRecentlySynced(const PhysicalDeviceKey &deviceKey) const
{
    auto it = syncedPeers_.find(deviceKey);
    if (it == syncedPeers_.end()) {
        IAM_LOGD("device %{public}s never synced with us, skip resync", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        return false;
    }

    auto now = GetTimeKeeper().GetSteadyTimeMs();
    if (!now.has_value()) {
        IAM_LOGE("failed to get steady time");
        return false;
    }

    auto elapsedMs = SafeSub(now.value(), it->second);
    if (!elapsedMs.has_value() || elapsedMs.value() >= SYNCED_PEER_TTL_MS) {
        IAM_LOGD("device %{public}s sync record expired, skip resync", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        return false;
    }
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
