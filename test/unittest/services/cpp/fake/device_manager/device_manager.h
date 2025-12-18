/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FAKE_DEVICE_MANAGER_H
#define FAKE_DEVICE_MANAGER_H

#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {

constexpr size_t DM_MAX_DEVICE_ID_LEN = 97;
constexpr size_t DM_MAX_DEVICE_NAME_LEN = 129;

enum class DmDeviceType : uint16_t {
    DEVICE_TYPE_UNKNOWN = 0x00,
    DEVICE_TYPE_PC = 0x0C,
    DEVICE_TYPE_PHONE = 0x0E,
    DEVICE_TYPE_PAD = 0x11,
    DEVICE_TYPE_WATCH = 0x6D,
    DEVICE_TYPE_TV = 0x9C,
    DEVICE_TYPE_SMART_DISPLAY = 0xA02,
    DEVICE_TYPE_2IN1 = 0xA2F,
};

enum class DmAuthForm : int32_t {
    INVALID_TYPE = -1,
    PEER_TO_PEER = 0,
    IDENTICAL_ACCOUNT = 1,
    ACROSS_ACCOUNT = 2,
    SHARE = 3,
};

struct DmDeviceBasicInfo {
    char deviceId[DM_MAX_DEVICE_ID_LEN] = {};
    char deviceName[DM_MAX_DEVICE_NAME_LEN] = {};
    uint16_t deviceTypeId = static_cast<uint16_t>(DmDeviceType::DEVICE_TYPE_UNKNOWN);
};

struct DmDeviceInfo : public DmDeviceBasicInfo {
    char networkId[DM_MAX_DEVICE_ID_LEN] = {};
    int32_t range = 0;
    int32_t networkType = 0;
    DmAuthForm authForm = DmAuthForm::INVALID_TYPE;
    std::string extraData;
};

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
    static DeviceManager &GetInstance();

    int32_t InitDeviceManager(const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback);
    int32_t UnInitDeviceManager(const std::string &pkgName);
    int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList);
    int32_t GetLocalDeviceInfo(const std::string &pkgName, DmDeviceInfo &info);
    int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &netWorkId, std::string &udid);
    int32_t RegisterDevStatusCallback(const std::string &pkgName, const std::string &extra,
        std::shared_ptr<DeviceStatusCallback> callback);
    int32_t UnRegisterDevStatusCallback(const std::string &pkgName);
};

} // namespace DistributedHardware
} // namespace OHOS

#endif // FAKE_DEVICE_MANAGER_H
