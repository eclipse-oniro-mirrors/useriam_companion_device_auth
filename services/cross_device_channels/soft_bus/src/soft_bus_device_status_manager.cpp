/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_device_status_manager.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <map>

#include "device_manager.h"
#include "system_ability_definition.h"
#include <nlohmann/json.hpp>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_channel_common.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace DistributedHardware;
using json = nlohmann::json;

std::shared_ptr<SoftBusDeviceStatusManager> SoftBusDeviceStatusManager::Create()
{
    auto manager = std::shared_ptr<SoftBusDeviceStatusManager>(new (std::nothrow) SoftBusDeviceStatusManager());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (!manager->Initialize()) {
        IAM_LOGE("Initialize SoftBusDeviceStatusManager failed");
        return nullptr;
    }
    IAM_LOGI("SoftBusDeviceStatusManager created successfully");
    return manager;
}

SoftBusDeviceStatusManager::SoftBusDeviceStatusManager()
{
}

bool SoftBusDeviceStatusManager::IsDeviceTypeIdSupport(DmDeviceType deviceTypeId)
{
    // RK3568 device type is unknown
    return deviceTypeId == DmDeviceType::DEVICE_TYPE_PHONE || deviceTypeId == DmDeviceType::DEVICE_TYPE_PAD ||
        deviceTypeId == DmDeviceType::DEVICE_TYPE_2IN1 || deviceTypeId == DmDeviceType::DEVICE_TYPE_PC ||
        deviceTypeId == DmDeviceType::DEVICE_TYPE_UNKNOWN;
}

std::string SoftBusDeviceStatusManager::DeviceTypeIdToString(DmDeviceType deviceTypeId)
{
    switch (deviceTypeId) {
        case DmDeviceType::DEVICE_TYPE_PC:
            return "pc";
        case DmDeviceType::DEVICE_TYPE_PHONE:
            return "phone";
        case DmDeviceType::DEVICE_TYPE_PAD:
            return "pad";
        case DmDeviceType::DEVICE_TYPE_2IN1:
            return "2in1";
        // RK3568 device type is unknown
        case DmDeviceType::DEVICE_TYPE_UNKNOWN:
            return "unknown";
        default:
            IAM_LOGE("unsupported device type: %{public}d", static_cast<uint32_t>(deviceTypeId));
            return "unknown";
    }
}

std::string SoftBusDeviceStatusManager::GenerateDeviceModelInfo(DmDeviceType deviceTypeId)
{
    json deviceInfo;
    deviceInfo["type"] = "deviceType";
    deviceInfo["deviceType"] = DeviceTypeIdToString(deviceTypeId);
    return deviceInfo.dump();
}

class DeviceStatusCallbackImpl : public DeviceStatusCallback {
public:
    explicit DeviceStatusCallbackImpl(std::weak_ptr<SoftBusDeviceStatusManager> manager) : manager_(manager)
    {
    }

    ~DeviceStatusCallbackImpl() override = default;

    void OnDeviceOnline([[maybe_unused]] const DmDeviceBasicInfo &deviceBasicInfo) override
    {
        IAM_LOGI("receive device online event");
        RefreshDeviceStatus();
    }

    void OnDeviceOffline(const DmDeviceBasicInfo &deviceBasicInfo) override
    {
        (void)deviceBasicInfo;
        IAM_LOGI("receive device offline event");
        RefreshDeviceStatus();
    }

    void OnDeviceChanged(const DmDeviceBasicInfo &deviceBasicInfo) override
    {
        (void)deviceBasicInfo;
        IAM_LOGI("receive device changed event");
        RefreshDeviceStatus();
    }

    void OnDeviceReady(const DmDeviceBasicInfo &deviceBasicInfo) override
    {
        (void)deviceBasicInfo;
        IAM_LOGI("receive device ready event");
        RefreshDeviceStatus();
    }

private:
    void RefreshDeviceStatus()
    {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weak_manager = manager_]() {
            auto manager = weak_manager.lock();
            ENSURE_OR_RETURN(manager != nullptr);
            manager->RefreshDeviceStatus();
        });
    }

    std::weak_ptr<SoftBusDeviceStatusManager> manager_;
};

SoftBusDeviceStatusManager::~SoftBusDeviceStatusManager()
{
    UnregisterDeviceStatusCallback();
    UnInitDeviceManager();
}

bool SoftBusDeviceStatusManager::Initialize()
{
    return true;
}

bool SoftBusDeviceStatusManager::Start()
{
    if (started_) {
        IAM_LOGI("SoftBusDeviceStatusManager already started");
        return true;
    }

    constexpr const char *DEVICE_MANAGER_SA_NAME = "DeviceManagerService";

    std::weak_ptr<SoftBusDeviceStatusManager> weakSelf = weak_from_this();
    saStatusListener_ = SaStatusListener::Create(
        DEVICE_MANAGER_SA_NAME, DISTRIBUTED_HARDWARE_DEVICEMANAGER_SA_ID,
        [weakSelf]() {
            TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf]() {
                auto manager = weakSelf.lock();
                ENSURE_OR_RETURN(manager != nullptr);
                manager->HandleDeviceManagerServiceReady();
            });
        },
        [weakSelf]() {
            TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf]() {
                auto manager = weakSelf.lock();
                ENSURE_OR_RETURN(manager != nullptr);
                manager->HandleDeviceManagerServiceUnavailable();
            });
        });
    ENSURE_OR_RETURN_VAL(saStatusListener_ != nullptr, false);

    systemParamSubscription_ =
        GetSystemParamManager().WatchParam(IS_AUTH_MAINTAIN_ACTIVE_KEY, [weakSelf](const std::string &value) {
            bool isAuthMaintainActive = value == TRUE_STR;
            TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf, isAuthMaintainActive]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleLocalIsAuthMaintainActiveChange(isAuthMaintainActive);
            });
        });
    ENSURE_OR_RETURN_VAL(systemParamSubscription_ != nullptr, false);
    auto initialIsLocalAuthMaintainActive =
        GetSystemParamManager().GetParam(IS_AUTH_MAINTAIN_ACTIVE_KEY, FALSE_STR) == TRUE_STR;
    HandleLocalIsAuthMaintainActiveChange(initialIsLocalAuthMaintainActive);

    started_ = true;
    return true;
}

bool SoftBusDeviceStatusManager::InitDeviceManager()
{
    if (dmInitialized_) {
        IAM_LOGI("DeviceManager already initialized");
        return true;
    }

    if (!GetDeviceManagerAdapter().InitDeviceManager()) {
        IAM_LOGE("InitDeviceManager failed");
        return false;
    }

    dmInitialized_ = true;
    IAM_LOGI("DeviceManager initialized");
    return true;
}

void SoftBusDeviceStatusManager::UnInitDeviceManager()
{
    if (!dmInitialized_) {
        return;
    }

    GetDeviceManagerAdapter().UnInitDeviceManager();

    dmInitialized_ = false;
    IAM_LOGI("DeviceManager uninitialized");
}

void SoftBusDeviceStatusManager::RefreshDeviceStatus()
{
    IAM_LOGI("refresh device status begin");
    std::vector<DmDeviceInfo> deviceList;
    if (!QueryTrustedDevices(deviceList)) {
        IAM_LOGE("QueryTrustedDevices failed");
        return;
    }

    std::vector<PhysicalDeviceStatus> statuses;
    if (!ConvertToPhysicalDevices(deviceList, statuses)) {
        IAM_LOGE("ConvertToPhysicalDevices failed");
        return;
    }

    if (statuses == physicalDeviceStatus_) {
        IAM_LOGI("No changes in physical device statuses");
        return;
    }
    physicalDeviceStatus_ = std::move(statuses);

    NotifyDeviceStatusChange();
    IAM_LOGI("refresh device status success");
}

bool SoftBusDeviceStatusManager::QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList)
{
    if (!GetDeviceManagerAdapter().QueryTrustedDevices(deviceList)) {
        IAM_LOGE("QueryTrustedDevices failed");
        return false;
    }

    IAM_LOGI("trusted devices num: %{public}zu", deviceList.size());
    auto it = std::remove_if(deviceList.begin(), deviceList.end(), [](const DmDeviceInfo &device) {
        DmDeviceType deviceTypeId = static_cast<DmDeviceType>(device.deviceTypeId);
        if (!IsDeviceTypeIdSupport(deviceTypeId)) {
            IAM_LOGI("device type not supported: %{public}d", static_cast<uint32_t>(deviceTypeId));
            return true;
        }
        return false;
    });
    deviceList.erase(it, deviceList.end());

    return true;
}

bool SoftBusDeviceStatusManager::ConvertToPhysicalDevices(const std::vector<DmDeviceInfo> &deviceList,
    std::vector<PhysicalDeviceStatus> &retPhysicalDeviceStatuses)
{
    retPhysicalDeviceStatuses.reserve(deviceList.size());

    for (const auto &device : deviceList) {
        std::string networkId(device.networkId, strnlen(device.networkId, DM_MAX_DEVICE_ID_LEN));
        auto deviceIdResult = GetDeviceManagerAdapter().GetUdidByNetworkId(networkId);
        if (!deviceIdResult.has_value()) {
            IAM_LOGE("GetUdidByNetworkId failed for networkId %{public}s", GetMaskedString(networkId).c_str());
            continue;
        }
        std::string deviceModelInfo =
            SoftBusDeviceStatusManager::GenerateDeviceModelInfo(static_cast<DmDeviceType>(device.deviceTypeId));
        IAM_LOGI("Device %{public}s model info: %{public}s", GetMaskedString(deviceIdResult.value()).c_str(),
            deviceModelInfo.c_str());

        retPhysicalDeviceStatuses.emplace_back(
            PhysicalDeviceStatus { PhysicalDeviceKey { DeviceIdType::UNIFIED_DEVICE_ID, deviceIdResult.value() },
                ChannelId::SOFTBUS, device.deviceName, deviceModelInfo, networkId, true });
    }

    return true;
}

void SoftBusDeviceStatusManager::NotifyDeviceStatusChange()
{
    if (physicalDeviceStatusSubscribers_.empty()) {
        return;
    }

    std::map<int32_t, OnPhysicalDeviceStatusChange> subscribers = physicalDeviceStatusSubscribers_;
    std::vector<PhysicalDeviceStatus> notifyStatuses = physicalDeviceStatus_;
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [subscribers, notifyStatuses = std::move(notifyStatuses)]() mutable {
            for (const auto &pair : subscribers) {
                if (pair.second != nullptr) {
                    pair.second(notifyStatuses);
                }
            }
        });
}

void SoftBusDeviceStatusManager::NotifyAuthMaintainActiveChange()
{
    if (authMaintainActiveSubscribers_.empty()) {
        return;
    }

    std::map<int32_t, OnAuthMaintainActiveChange> subscribers = authMaintainActiveSubscribers_;
    bool isActive = isLocalAuthMaintainActive_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([subscribers, isActive]() mutable {
        for (const auto &pair : subscribers) {
            if (pair.second != nullptr) {
                pair.second(isActive);
            }
        }
    });
}

std::unique_ptr<Subscription> SoftBusDeviceStatusManager::SubscribePhysicalDeviceStatus(
    OnPhysicalDeviceStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    physicalDeviceStatusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("physical device status subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribePhysicalDeviceStatus(subscriptionId);
    });
}

void SoftBusDeviceStatusManager::UnsubscribePhysicalDeviceStatus(SubscribeId subscriptionId)
{
    physicalDeviceStatusSubscribers_.erase(subscriptionId);
    IAM_LOGD("physical device status subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

std::vector<PhysicalDeviceStatus> SoftBusDeviceStatusManager::GetAllPhysicalDevices() const
{
    return physicalDeviceStatus_;
}

std::unique_ptr<Subscription> SoftBusDeviceStatusManager::SubscribeAuthMaintainActive(
    OnAuthMaintainActiveChange &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    authMaintainActiveSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("auth maintain active subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeAuthMaintainActive(subscriptionId);
    });
}

void SoftBusDeviceStatusManager::UnsubscribeAuthMaintainActive(SubscribeId subscriptionId)
{
    authMaintainActiveSubscribers_.erase(subscriptionId);
    IAM_LOGD("auth maintain active subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

std::optional<PhysicalDeviceStatus> SoftBusDeviceStatusManager::GetPhysicalDeviceStatus(const PhysicalDeviceKey &key)
{
    auto it = std::find_if(physicalDeviceStatus_.begin(), physicalDeviceStatus_.end(),
        [&key](const PhysicalDeviceStatus &status) { return status.physicalDeviceKey == key; });
    if (it == physicalDeviceStatus_.end()) {
        IAM_LOGE("PhysicalDeviceStatus not found for key");
        return std::nullopt;
    }
    return *it;
}

bool SoftBusDeviceStatusManager::GetAuthMaintainActive() const
{
    return isLocalAuthMaintainActive_;
}

std::optional<PhysicalDeviceKey> SoftBusDeviceStatusManager::GetLocalPhysicalDeviceKey() const
{
    auto localUdid = GetMiscManager().GetLocalUdid();
    if (!localUdid.has_value()) {
        IAM_LOGE("GetLocalPhysicalDeviceKey failed, GetLocalUdid error");
        return std::nullopt;
    }

    const auto &deviceId = localUdid.value();
    PhysicalDeviceKey key {};
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = deviceId;
    IAM_LOGI("GetLocalPhysicalDeviceKey success, deviceId: %{public}s", GetMaskedString(deviceId).c_str());
    return key;
}

void SoftBusDeviceStatusManager::HandleLocalIsAuthMaintainActiveChange(bool isAuthMaintainActive)
{
    if (isLocalAuthMaintainActive_ == isAuthMaintainActive) {
        IAM_LOGI("isAuthMaintainActive is already set to %{public}d", isAuthMaintainActive);
        return;
    }
    IAM_LOGI("update isAuthMaintainActive to %{public}d", isAuthMaintainActive);
    isLocalAuthMaintainActive_ = isAuthMaintainActive;
    NotifyAuthMaintainActiveChange();
}

void SoftBusDeviceStatusManager::HandleDeviceManagerServiceReady()
{
    IAM_LOGI("DeviceManager SA is ready");

    if (!InitDeviceManager()) {
        IAM_LOGE("Failed to init device manager after SA ready");
        return;
    }

    bool ret = RegisterDeviceStatusCallback();
    if (!ret) {
        IAM_LOGE("Failed to register device status callback after SA ready");
        return;
    }

    RefreshDeviceStatus();
}

void SoftBusDeviceStatusManager::HandleDeviceManagerServiceUnavailable()
{
    IAM_LOGI("DeviceManager SA is unavailable");

    physicalDeviceStatus_.clear();
    NotifyDeviceStatusChange();

    UnregisterDeviceStatusCallback();
    UnInitDeviceManager();
}

bool SoftBusDeviceStatusManager::RegisterDeviceStatusCallback()
{
    if (dsCallback_ != nullptr) {
        IAM_LOGE("dsCallback is already set");
        return true;
    }

    auto dsCallback = std::make_shared<DeviceStatusCallbackImpl>(weak_from_this());
    ENSURE_OR_RETURN_VAL(dsCallback != nullptr, false);
    if (!GetDeviceManagerAdapter().RegisterDevStatusCallback(dsCallback)) {
        IAM_LOGE("RegisterDevStatusCallback failed");
        return false;
    }

    dsCallback_ = dsCallback;
    IAM_LOGI("success");
    return true;
}

void SoftBusDeviceStatusManager::UnregisterDeviceStatusCallback()
{
    if (dsCallback_ != nullptr) {
        GetDeviceManagerAdapter().UnRegisterDevStatusCallback(dsCallback_);
        dsCallback_ = nullptr;
    }
    IAM_LOGI("success");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
