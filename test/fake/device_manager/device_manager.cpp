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

#include "device_manager.h"

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "securec.h"

namespace OHOS {
namespace DistributedHardware {

DeviceManager &DeviceManager::GetInstance()
{
    static DeviceManager instance;
    return instance;
}

int32_t DeviceManager::InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback)
{
    (void)pkgName;
    (void)dmInitCallback;
    return 0;
}

int32_t DeviceManager::UnInitDeviceManager(const std::string &pkgName)
{
    (void)pkgName;
    return 0;
}

int32_t DeviceManager::GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
    std::vector<DmDeviceInfo> &deviceList)
{
    (void)pkgName;
    (void)extra;
    (void)deviceList;
    return 0;
}

int32_t DeviceManager::GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &info)
{
    (void)pkgName;
    (void)info;
    return 0;
}

int32_t DeviceManager::GetUdidByNetworkId(const std::string &pkgName, const std::string &netWorkId, std::string &udid)
{
    (void)pkgName;
    (void)netWorkId;
    (void)udid;
    return 0;
}

int32_t DeviceManager::RegisterDevStatusCallback(const std::string &pkgName, const std::string &extra,
    std::shared_ptr<DeviceStatusCallback> callback)
{
    (void)pkgName;
    (void)extra;
    (void)callback;
    return 0;
}

int32_t DeviceManager::UnRegisterDevStatusCallback(const std::string &pkgName)
{
    (void)pkgName;
    return 0;
}

} // namespace DistributedHardware
} // namespace OHOS
