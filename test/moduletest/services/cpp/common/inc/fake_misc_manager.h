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

#ifndef COMPANION_DEVICE_AUTH_FAKE_MISC_MANAGER_H
#define COMPANION_DEVICE_AUTH_FAKE_MISC_MANAGER_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "misc_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeMiscManager : public IMiscManager {
public:
    FakeMiscManager() = default;
    ~FakeMiscManager() override = default;

    uint64_t GetNextGlobalId() override
    {
        return counter_++;
    }

    bool SetDeviceSelectCallback(uint32_t tokenId, const sptr<IIpcDeviceSelectCallback> &cb) override
    {
        callbacks_[tokenId] = cb;
        return true;
    }

    bool GetDeviceDeviceSelectResult(uint32_t tokenId, SelectPurpose, DeviceSelectResultHandler &&handler) override
    {
        auto it = callbacks_.find(tokenId);
        if (it == callbacks_.end()) {
            return false;
        }
        pendingHandlers_[tokenId] = std::move(handler);
        return true;
    }

    void ClearDeviceSelectCallback(uint32_t tokenId) override
    {
        callbacks_.erase(tokenId);
        pendingHandlers_.erase(tokenId);
    }

    std::optional<std::string> GetLocalUdid() override
    {
        return udid_;
    }

    void SetCompanionAuthBlocked(bool blocked) override
    {
        blocked_ = blocked;
    }

    bool IsCompanionAuthBlocked() const override
    {
        return blocked_;
    }

    bool SetPasscodePromptCallback(uint32_t, const sptr<IIpcPasscodePromptCallback> &) override
    {
        return true;
    }

    void ClearPasscodePromptCallback(uint32_t) override
    {
    }

    bool PromptPasscode(uint32_t, const std::vector<uint8_t> &, const std::vector<uint8_t> &, AsymEncryptAlgorithm,
        PasscodePromptCallback &&) override
    {
        return true;
    }

    // Test backdoors
    void TestSetLocalUdid(const std::string &udid)
    {
        udid_ = udid;
    }

    void TestSimulateDeviceSelectResult(uint32_t tokenId, const std::vector<DeviceKey> &selectedDevices)
    {
        auto it = pendingHandlers_.find(tokenId);
        if (it != pendingHandlers_.end() && it->second) {
            it->second(selectedDevices, std::nullopt);
            pendingHandlers_.erase(it);
        }
    }

private:
    std::atomic<uint64_t> counter_ { 1 };
    std::string udid_ = "test-udid-12345";
    bool blocked_ { false };
    std::map<uint32_t, sptr<IIpcDeviceSelectCallback>> callbacks_;
    std::map<uint32_t, DeviceSelectResultHandler> pendingHandlers_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_MISC_MANAGER_H
