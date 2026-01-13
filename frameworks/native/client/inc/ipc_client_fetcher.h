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

#ifndef IPC_CLIENT_FETCHER_H
#define IPC_CLIENT_FETCHER_H

#include <functional>
#include <memory>

#include "icompanion_device_auth.h"
#include "iremote_object.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using DeathCallback = std::function<void(const wptr<IRemoteObject> &remote)>;

class IpcClientFetcher {
public:
    static sptr<ICompanionDeviceAuth> GetProxy(const DeathCallback &deathCallback);

private:
    static sptr<IRemoteObject> GetRemoteObject();
    static sptr<IRemoteObject::DeathRecipient> CreateDeathRecipient(const DeathCallback &callback);
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // IPC_CLIENT_FETCHER_H
