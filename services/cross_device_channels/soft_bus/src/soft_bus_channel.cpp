/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_channel.h"

#include <algorithm>
#include <new>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_types.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_channel_common.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using namespace DistributedHardware;

std::shared_ptr<SoftBusChannel> SoftBusChannel::Create()
{
    std::shared_ptr<SoftBusChannel> channel(new (std::nothrow) SoftBusChannel());
    ENSURE_OR_RETURN_VAL(channel != nullptr, nullptr);
    if (!channel->Initialize()) {
        IAM_LOGE("SoftBusChannel initialize failed");
        return nullptr;
    }
    return channel;
}

SoftBusChannel::SoftBusChannel()
{
}

bool SoftBusChannel::Initialize()
{
    if (!SoftBusAdapterManager::GetInstance().CreateAndRegisterAdapters()) {
        IAM_LOGE("Failed to initialize SoftBus adapter manager");
        return false;
    }

    connectionManager_ = SoftBusConnectionManager::Create();
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, false);

    deviceStatusManager_ = SoftBusDeviceStatusManager::Create();
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, false);

    IAM_LOGI("SoftBusChannel initialized");
    return true;
}

bool SoftBusChannel::Start()
{
    if (started_) {
        IAM_LOGI("SoftBusChannel already started");
        return true;
    }

    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, false);

    if (!connectionManager_->Start()) {
        IAM_LOGE("SoftBusConnectionManager start failed");
        return false;
    }

    if (!deviceStatusManager_->Start()) {
        IAM_LOGE("SoftBusDeviceStatusManager start failed");
        return false;
    }

    started_ = true;
    IAM_LOGI("SoftBusChannel started");
    return true;
}

ChannelId SoftBusChannel::GetChannelId() const
{
    return ChannelId::SOFTBUS;
}

std::optional<PhysicalDeviceKey> SoftBusChannel::GetLocalPhysicalDeviceKey() const
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, std::nullopt);
    return deviceStatusManager_->GetLocalPhysicalDeviceKey();
}

bool SoftBusChannel::OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey)
{
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, false);

    std::optional<PhysicalDeviceStatus> status = deviceStatusManager_->GetPhysicalDeviceStatus(physicalDeviceKey);
    ENSURE_OR_RETURN_VAL(status.has_value(), false);

    return connectionManager_->OpenConnection(connectionName, physicalDeviceKey, status->networkId);
}

void SoftBusChannel::CloseConnection(const std::string &connectionName)
{
    ENSURE_OR_RETURN(connectionManager_ != nullptr);

    connectionManager_->CloseConnection(connectionName);
}

bool SoftBusChannel::SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
{
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, false);

    return connectionManager_->SendMessage(connectionName, rawMsg);
}

std::vector<PhysicalDeviceStatus> SoftBusChannel::GetAllPhysicalDevices() const
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, std::vector<PhysicalDeviceStatus>());
    return deviceStatusManager_->GetAllPhysicalDevices();
}

std::unique_ptr<Subscription> SoftBusChannel::SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, nullptr);
    return deviceStatusManager_->SubscribePhysicalDeviceStatus(std::move(callback));
}

std::unique_ptr<Subscription> SoftBusChannel::SubscribeRawMessage(OnRawMessage &&callback)
{
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, nullptr);
    return connectionManager_->SubscribeRawMessage(std::move(callback));
}

std::unique_ptr<Subscription> SoftBusChannel::SubscribeConnectionStatus(OnConnectionStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, nullptr);
    return connectionManager_->SubscribeConnectionStatus(std::move(callback));
}

std::unique_ptr<Subscription> SoftBusChannel::SubscribeIncomingConnection(OnIncomingConnection &&callback)
{
    ENSURE_OR_RETURN_VAL(connectionManager_ != nullptr, nullptr);
    return connectionManager_->SubscribeIncomingConnection(std::move(callback));
}

bool SoftBusChannel::GetAuthMaintainActive() const
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, false);
    return deviceStatusManager_->GetAuthMaintainActive();
}

std::unique_ptr<Subscription> SoftBusChannel::SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback)
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager_ != nullptr, nullptr);
    return deviceStatusManager_->SubscribeAuthMaintainActive(std::move(callback));
}

SecureProtocolId SoftBusChannel::GetCompanionSecureProtocolId() const
{
    return SecureProtocolId::DEFAULT;
}

bool SoftBusChannel::CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
    OnCheckOperationIntentResult &&resultCallback)
{
    if (!resultCallback) {
        IAM_LOGE("resultCallback invalid");
        return false;
    }

    bool requestStarted = GetMiscManager().GetDeviceDeviceSelectResult(tokenId, SelectPurpose::CHECK_OPERATION_INTENT,
        [deviceKey, callback = std::move(resultCallback)](const std::vector<DeviceKey> &selectedDevices) mutable {
            bool confirmed = false;
            if (selectedDevices.empty()) {
                IAM_LOGE("no device selected by user");
            } else {
                confirmed = std::any_of(selectedDevices.begin(), selectedDevices.end(),
                    [&deviceKey](const DeviceKey &selectedDevice) {
                        return deviceKey.idType == selectedDevice.idType &&
                            deviceKey.deviceId == selectedDevice.deviceId &&
                            deviceKey.deviceUserId == selectedDevice.deviceUserId;
                    });
                if (confirmed) {
                    IAM_LOGI("user confirmed operation for device: %{public}s", deviceKey.GetDesc().c_str());
                } else {
                    IAM_LOGE("user did not select target device: %{public}s", deviceKey.GetDesc().c_str());
                }
            }

            TaskRunnerManager::GetInstance().PostTaskOnResident([cb = std::move(callback), confirmed]() mutable {
                if (cb) {
                    cb(confirmed);
                }
            });
        });
    if (!requestStarted) {
        IAM_LOGE("failed to request device select result");
        return false;
    }

    return true;
}

bool SoftBusChannel::RequiresDisconnectNotification() const
{
    return false;
}

void SoftBusChannel::OnRemoteDisconnect(const std::string &connectionName, const std::string &reason)
{
    IAM_LOGI("OnRemoteDisconnect: conn=%{public}s, reason=%{public}s", connectionName.c_str(), reason.c_str());

    if (connectionManager_ != nullptr) {
        connectionManager_->CloseConnection(connectionName);
    }
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
