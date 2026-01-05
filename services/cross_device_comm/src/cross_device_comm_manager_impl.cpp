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

#include "cross_device_comm_manager_impl.h"

#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "channel_manager.h"
#include "connection_manager.h"
#include "device_status_manager.h"
#include "local_device_status_manager.h"
#include "message_router.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<CrossDeviceCommManagerImpl> CrossDeviceCommManagerImpl::Create(
    const std::vector<std::shared_ptr<ICrossDeviceChannel>> &channels)
{
    ENSURE_OR_RETURN_VAL(channels.size() > 0, nullptr);

    auto channelMgr = std::make_shared<ChannelManager>(channels);
    ENSURE_OR_RETURN_VAL(channelMgr != nullptr, nullptr);

    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr);
    ENSURE_OR_RETURN_VAL(localDeviceStatusMgr != nullptr, nullptr);

    auto connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    ENSURE_OR_RETURN_VAL(connectionMgr != nullptr, nullptr);

    auto messageRouter = MessageRouter::Create(connectionMgr, channelMgr);
    ENSURE_OR_RETURN_VAL(messageRouter != nullptr, nullptr);
    connectionMgr->SetMessageRouter(messageRouter);

    auto deviceStatusMgr = DeviceStatusManager::Create(connectionMgr, channelMgr, localDeviceStatusMgr);
    ENSURE_OR_RETURN_VAL(deviceStatusMgr != nullptr, nullptr);

    auto manager = std::shared_ptr<CrossDeviceCommManagerImpl>(new CrossDeviceCommManagerImpl(channelMgr,
        localDeviceStatusMgr, connectionMgr, messageRouter, deviceStatusMgr));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    IAM_LOGI("create success");
    return manager;
}

CrossDeviceCommManagerImpl::CrossDeviceCommManagerImpl(std::shared_ptr<ChannelManager> channelMgr,
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr, std::shared_ptr<ConnectionManager> connectionMgr,
    std::shared_ptr<MessageRouter> messageRouter, std::shared_ptr<DeviceStatusManager> deviceStatusMgr)
    : channelMgr_(channelMgr),
      localDeviceStatusMgr_(localDeviceStatusMgr),
      connectionMgr_(connectionMgr),
      messageRouter_(messageRouter),
      deviceStatusMgr_(deviceStatusMgr)
{
}

bool CrossDeviceCommManagerImpl::Start()
{
    if (started_) {
        IAM_LOGI("already started");
        return true;
    }

    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ENSURE_OR_RETURN_VAL(channel != nullptr, false);
        if (!channel->Start()) {
            IAM_LOGE("failed to start channel %{public}d", static_cast<int32_t>(channel->GetChannelId()));
            return false;
        }
    }

    started_ = true;
    IAM_LOGI("start success");
    return true;
}

bool CrossDeviceCommManagerImpl::IsAuthMaintainActive()
{
    return localDeviceStatusMgr_->IsAuthMaintainActive();
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeIsAuthMaintainActive(
    OnAuthMaintainActiveChange &&callback)
{
    return localDeviceStatusMgr_->SubscribeIsAuthMaintainActive(std::move(callback));
}

LocalDeviceProfile CrossDeviceCommManagerImpl::GetLocalDeviceProfile()
{
    return localDeviceStatusMgr_->GetLocalDeviceProfile();
}

std::optional<DeviceStatus> CrossDeviceCommManagerImpl::GetDeviceStatus(const DeviceKey &deviceKey)
{
    return deviceStatusMgr_->GetDeviceStatus(deviceKey);
}

std::vector<DeviceStatus> CrossDeviceCommManagerImpl::GetAllDeviceStatus()
{
    return deviceStatusMgr_->GetAllDeviceStatus();
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeAllDeviceStatus(
    OnDeviceStatusChange &&onDeviceStatusChange)
{
    return deviceStatusMgr_->SubscribeDeviceStatus(std::move(onDeviceStatusChange));
}

void CrossDeviceCommManagerImpl::SetSubscribeMode(SubscribeMode subscribeMode)
{
    deviceStatusMgr_->SetSubscribeMode(subscribeMode);
}

std::optional<int64_t> CrossDeviceCommManagerImpl::GetManageSubscribeTime() const
{
    return deviceStatusMgr_->GetManageSubscribeTime();
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeDeviceStatus(const DeviceKey &deviceKey,
    OnDeviceStatusChange &&onDeviceStatusChange)
{
    return deviceStatusMgr_->SubscribeDeviceStatus(deviceKey, std::move(onDeviceStatusChange));
}

bool CrossDeviceCommManagerImpl::OpenConnection(const DeviceKey &deviceKey, std::string &outConnectionName)
{
    auto channelId = deviceStatusMgr_->GetChannelIdByDeviceKey(deviceKey);
    if (!channelId.has_value()) {
        IAM_LOGE("failed to get channel id for device: %{public}s", deviceKey.GetDesc().c_str());
        return false;
    }

    PhysicalDeviceKey physicalDeviceKey;
    physicalDeviceKey.idType = deviceKey.idType;
    physicalDeviceKey.deviceId = deviceKey.deviceId;

    return connectionMgr_->OpenConnection(physicalDeviceKey, channelId.value(), outConnectionName);
}

void CrossDeviceCommManagerImpl::CloseConnection(const std::string &connectionName)
{
    connectionMgr_->CloseConnection(connectionName);
}

bool CrossDeviceCommManagerImpl::IsConnectionOpen(const std::string &connectionName)
{
    return GetConnectionStatus(connectionName) == ConnectionStatus::CONNECTED;
}

ConnectionStatus CrossDeviceCommManagerImpl::GetConnectionStatus(const std::string &connectionName)
{
    return connectionMgr_->GetConnectionStatus(connectionName);
}

std::optional<DeviceKey> CrossDeviceCommManagerImpl::GetLocalDeviceKeyByConnectionName(
    const std::string &connectionName)
{
    ENSURE_OR_RETURN_VAL(!connectionName.empty(), std::nullopt);
    auto connection = connectionMgr_->GetConnection(connectionName);
    if (!connection.has_value()) {
        IAM_LOGE("connection not found %{public}s", connectionName.c_str());
        return std::nullopt;
    }

    return localDeviceStatusMgr_->GetLocalDeviceKey(connection->channelId);
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeConnectionStatus(const std::string &connectionName,
    OnConnectionStatusChange &&onConnectionStatusChange)
{
    return connectionMgr_->SubscribeConnectionStatus(connectionName, std::move(onConnectionStatusChange));
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeIncomingConnection(MessageType msgType,
    OnMessage &&onMessage)
{
    return messageRouter_->SubscribeIncomingConnection(msgType, std::move(onMessage));
}

bool CrossDeviceCommManagerImpl::SendMessage(const std::string &connectionName, MessageType msgType,
    Attributes &request, OnMessageReply &&onMessageReply)
{
    return messageRouter_->SendMessage(connectionName, msgType, request, std::move(onMessageReply));
}

std::unique_ptr<Subscription> CrossDeviceCommManagerImpl::SubscribeMessage(const std::string &connectionName,
    MessageType msgType, OnMessage &&onMessage)
{
    return messageRouter_->SubscribeMessage(connectionName, msgType, std::move(onMessage));
}

bool CrossDeviceCommManagerImpl::CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
    OnCheckOperationIntentResult &&resultCallback)
{
    if (!resultCallback) {
        IAM_LOGE("resultCallback invalid");
        return false;
    }

    auto channelId = deviceStatusMgr_->GetChannelIdByDeviceKey(deviceKey);
    ENSURE_OR_RETURN_VAL(channelId.has_value(), false);

    auto channel = channelMgr_->GetChannelById(channelId.value());
    ENSURE_OR_RETURN_VAL(channel != nullptr, false);
    return channel->CheckOperationIntent(deviceKey, tokenId, std::move(resultCallback));
}

std::optional<SecureProtocolId> CrossDeviceCommManagerImpl::HostGetSecureProtocolId(const DeviceKey &companionDeviceKey)
{
    auto deviceStatusOpt = GetDeviceStatus(companionDeviceKey);
    if (!deviceStatusOpt.has_value()) {
        IAM_LOGE("companion status not found for device: %{public}s", companionDeviceKey.GetDesc().c_str());
        return std::nullopt;
    }

    return deviceStatusOpt->secureProtocolId;
}

SecureProtocolId CrossDeviceCommManagerImpl::CompanionGetSecureProtocolId()
{
    LocalDeviceProfile profile = GetLocalDeviceProfile();
    return profile.companionSecureProtocolId;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
