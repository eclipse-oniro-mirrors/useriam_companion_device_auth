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

#ifndef COMPANION_DEVICE_AUTH_MISC_MANAGER_H
#define COMPANION_DEVICE_AUTH_MISC_MANAGER_H

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ipc_object_stub.h"
#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_types.h"
#include "iipc_device_select_callback.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INVALID_GLBOBAL_ID = -1;

using DeviceSelectResultHandler = std::function<void(const std::vector<DeviceKey> &)>;

class IMiscManager : public NoCopyable {
public:
    virtual ~IMiscManager() = default;

    virtual int32_t GetNextGlobalId() = 0;
    virtual bool SetDeviceSelectCallback(uint32_t tokenId,
        const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback) = 0;
    virtual bool GetDeviceDeviceSelectResult(uint32_t tokenId, SelectPurpose selectPurpose,
        DeviceSelectResultHandler &&resultHandler) = 0;
    virtual void ClearDeviceSelectCallback(uint32_t tokenId) = 0;
    virtual std::optional<std::string> GetLocalUdid() = 0;
    virtual uint32_t GetAccessTokenId(IPCObjectStub &stub) = 0;

protected:
    IMiscManager() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MISC_MANAGER_H
