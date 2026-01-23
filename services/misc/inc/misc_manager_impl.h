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

#ifndef COMPANION_DEVICE_AUTH_MISC_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_MISC_MANAGER_IMPL_H

#include <functional>
#include <map>
#include <memory>

#include "iremote_object.h"

#include "common_defines.h"
#include "misc_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MiscManagerImpl : public IMiscManager, public std::enable_shared_from_this<MiscManagerImpl> {
public:
    static std::shared_ptr<MiscManagerImpl> Create();

    ~MiscManagerImpl() override = default;

    uint64_t GetNextGlobalId() override;

    bool SetDeviceSelectCallback(uint32_t tokenId, const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback) override;
    bool GetDeviceDeviceSelectResult(uint32_t tokenId, SelectPurpose selectPurpose,
        DeviceSelectResultHandler &&resultHandler) override;
    void ClearDeviceSelectCallback(uint32_t tokenId) override;

    std::optional<std::string> GetLocalUdid() override;
    bool CheckBusinessIds(const std::vector<BusinessId> &businessIds) override;

private:
    MiscManagerImpl();
    struct CallbackInfo {
        sptr<IIpcDeviceSelectCallback> callback;
        sptr<IRemoteObject::DeathRecipient> deathRecipient;
    };

    uint64_t globalIdCounter_;
    std::map<uint32_t, CallbackInfo> callbacks_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MISC_MANAGER_IMPL_H
