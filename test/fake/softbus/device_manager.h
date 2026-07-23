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

#ifndef COMPANION_DEVICE_AUTH_FAKE_DEVICE_MANAGER_H
#define COMPANION_DEVICE_AUTH_FAKE_DEVICE_MANAGER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {

inline constexpr int32_t DM_MAX_DEVICE_ID_LEN = 96;

// Values MUST mirror the real SDK enum (foundation/distributedhardware/device_manager/.../dm_device_info.h).
// The implementation's switch/case compares on the numeric enum value, so a fake with divergent values makes
// every ConvertToDeviceType/DeviceTypeIdToString/IsDeviceTypeIdSupport call miss its case and fall through.
enum class DmDeviceType : int32_t {
    DEVICE_TYPE_UNKNOWN = 0x00,
    DEVICE_TYPE_PC = 0x0C,
    DEVICE_TYPE_PHONE = 0x0E,
    DEVICE_TYPE_PAD = 0x11,
    DEVICE_TYPE_2IN1 = 0xA2F,
};

struct DmDeviceInfo {
    int32_t deviceTypeId { 0 };
    char networkId[DM_MAX_DEVICE_ID_LEN] { 0 };
};

struct DmDeviceBasicInfo {};

class DmInitCallback {
public:
    virtual ~DmInitCallback() = default;
    virtual void OnRemoteDied() = 0;
};

class DeviceStatusCallback {
public:
    virtual ~DeviceStatusCallback() = default;
    virtual void OnDeviceOnline(const DmDeviceBasicInfo &deviceBasicInfo) = 0;
    virtual void OnDeviceOffline(const DmDeviceBasicInfo &deviceBasicInfo) = 0;
    virtual void OnDeviceChanged(const DmDeviceBasicInfo &deviceBasicInfo) = 0;
    virtual void OnDeviceReady(const DmDeviceBasicInfo &deviceBasicInfo) = 0;
};

class DeviceManager {
public:
    static DeviceManager &GetInstance()
    {
        static DeviceManager instance;
        return instance;
    }

    int32_t InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> callback)
    {
        (void)pkgName;
        (void)callback;
        return 0;
    }

    void UnInitDeviceManager(const std::string &pkgName)
    {
        (void)pkgName;
    }

    int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &networkId, std::string &udid)
    {
        (void)pkgName;
        (void)networkId;
        (void)udid;
        return -1;
    }

    int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList)
    {
        (void)pkgName;
        (void)extra;
        (void)deviceList;
        return -1;
    }

    int32_t RegisterDevStatusCallback(const std::string &pkgName, const std::string &extra,
        const std::shared_ptr<DeviceStatusCallback> &callback)
    {
        (void)pkgName;
        (void)extra;
        (void)callback;
        return -1;
    }

    void UnRegisterDevStatusCallback(const std::string &pkgName)
    {
        (void)pkgName;
    }

private:
    DeviceManager() = default;
    ~DeviceManager() = default;
    DeviceManager(const DeviceManager &) = delete;
    DeviceManager &operator=(const DeviceManager &) = delete;
};

} // namespace DistributedHardware
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_DEVICE_MANAGER_H
