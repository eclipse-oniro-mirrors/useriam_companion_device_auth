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

#include "device_manager_adapter_impl.h"

#include <cstdint>

#include "device_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "xcollie_helper.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using DeviceManager = DistributedHardware::DeviceManager;
using DmInitCallback = DistributedHardware::DmInitCallback;

namespace {
constexpr const char *PKG_NAME = "ohos.companiondeviceauth";

class DmInitCallbackImpl : public DmInitCallback {
public:
    void OnRemoteDied() override
    {
    }
};
} // namespace

std::shared_ptr<DeviceManagerAdapterImpl> DeviceManagerAdapterImpl::Create()
{
    auto adapter = std::shared_ptr<DeviceManagerAdapterImpl>(new (std::nothrow) DeviceManagerAdapterImpl());
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    if (!adapter->Initialize()) {
        IAM_LOGE("Failed to initialize DeviceManagerAdapterImpl");
        return nullptr;
    }
    return adapter;
}

bool DeviceManagerAdapterImpl::Initialize()
{
    return true;
}

bool DeviceManagerAdapterImpl::InitDeviceManager()
{
    auto callback = std::make_shared<DmInitCallbackImpl>();
    XCollieHelper xcollie("DeviceManagerAdapterImpl-InitDeviceManager", API_CALL_TIMEOUT);
    int32_t ret = DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, callback);
    if (ret != 0) {
        IAM_LOGE("InitDeviceManager failed: %{public}d", ret);
        return false;
    }
    return true;
}

void DeviceManagerAdapterImpl::UnInitDeviceManager()
{
    XCollieHelper xcollie("DeviceManagerAdapterImpl-UnInitDeviceManager", API_CALL_TIMEOUT);
    DeviceManager::GetInstance().UnInitDeviceManager(PKG_NAME);
}

std::optional<std::string> DeviceManagerAdapterImpl::GetUdidByNetworkId(const std::string &networkId)
{
    std::string udid;
    XCollieHelper xcollie("DeviceManagerAdapterImpl-GetUdidByNetworkId", API_CALL_TIMEOUT);
    int32_t ret = DeviceManager::GetInstance().GetUdidByNetworkId(PKG_NAME, networkId, udid);
    if (ret != 0 || udid.empty()) {
        IAM_LOGE("GetUdidByNetworkId failed: %{public}d", ret);
        return std::nullopt;
    }
    return udid;
}

bool DeviceManagerAdapterImpl::QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList)
{
    XCollieHelper xcollie("DeviceManagerAdapterImpl-QueryTrustedDevices", API_CALL_TIMEOUT);
    int32_t ret = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", deviceList);
    if (ret != 0) {
        IAM_LOGE("GetTrustedDeviceList failed: %{public}d", ret);
        return false;
    }
    return true;
}

bool DeviceManagerAdapterImpl::RegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback)
{
    std::string extra = "";
    XCollieHelper xcollie("DeviceManagerAdapterImpl-RegisterDevStatusCallback", API_CALL_TIMEOUT);
    int32_t ret = DeviceManager::GetInstance().RegisterDevStatusCallback(PKG_NAME, extra, callback);
    if (ret != 0) {
        IAM_LOGE("RegisterDevStatusCallback failed: %{public}d", ret);
        return false;
    }
    return true;
}

void DeviceManagerAdapterImpl::UnRegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback)
{
    (void)callback;
    XCollieHelper xcollie("DeviceManagerAdapterImpl-UnRegisterDevStatusCallback", API_CALL_TIMEOUT);
    DeviceManager::GetInstance().UnRegisterDevStatusCallback(PKG_NAME);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
