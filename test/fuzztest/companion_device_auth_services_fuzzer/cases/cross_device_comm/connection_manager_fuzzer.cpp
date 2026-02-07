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

#include <cstdint>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "channel_manager.h"
#include "connection_manager.h"
#include "fuzz_constants.h"
#include "fuzz_cross_device_channel.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "local_device_status_manager.h"
#include "message_router.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr uint32_t SIZE_128 = 128;
constexpr uint8_t UINT8_2 = 2;
} // namespace

using ConnectionManagerFuzzFunction = void (*)(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData);

static void FuzzGetConnection(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    auto connection = conn->GetConnection(connectionName);
    (void)connection;
}

static void FuzzGetConnectionStatus(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    auto status = conn->GetConnectionStatus(connectionName);
    (void)status;
}

static void FuzzOpenConnection(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    std::string outConnectionName;
    bool result = conn->OpenConnection(physicalKey, channelId, outConnectionName);
    (void)result;
}

static void FuzzCloseConnection(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    conn->CloseConnection(connectionName, reason);
}

static void FuzzHandleIncomingConnection(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    bool result = conn->HandleIncomingConnection(connectionName, physicalKey);
    (void)result;
}

static void FuzzSubscribeConnectionStatus(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    auto callback = [](const std::string &name, ConnectionStatus status, const std::string &reason) {
        (void)name;
        (void)status;
        (void)reason;
    };
    auto subscription = conn->SubscribeConnectionStatus(connectionName, std::move(callback));
    (void)subscription;
}

static void FuzzSetMessageRouter(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::weak_ptr<MessageRouter> weakRouter;
    conn->SetMessageRouter(weakRouter);
}

static void FuzzHandleChannelConnectionStatusChange(std::shared_ptr<ConnectionManager> &conn,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint8_t statusValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_2);
    ConnectionStatus status = static_cast<ConnectionStatus>(statusValue);
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    conn->HandleChannelConnectionStatusChange(connectionName, status, reason);
}

static void FuzzHandleKeepAliveReply(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    conn->HandleKeepAliveReply(connectionName, reply);
}

static void FuzzCheckResourceLimits(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    bool result = conn->CheckResourceLimits(physicalKey);
    (void)result;
}

static void FuzzCheckIdleMonitoring(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    conn->CheckIdleMonitoring();
}

static void FuzzHandleIdleMonitorTimer(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    conn->HandleIdleMonitorTimer();
}

static void FuzzNotifyConnectionStatus(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint8_t statusValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_2);
    ConnectionStatus status = static_cast<ConnectionStatus>(statusValue);
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    conn->NotifyConnectionStatus(connectionName, status, reason);
}

static void FuzzHandleChannelConnectionEstablished(std::shared_ptr<ConnectionManager> &conn,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    conn->HandleChannelConnectionEstablished(connectionName);
}

static void FuzzHandleChannelConnectionClosed(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    conn->HandleChannelConnectionClosed(connectionName, reason);
}

static void FuzzHandleIncomingConnectionFromChannel(std::shared_ptr<ConnectionManager> &conn,
    FuzzedDataProvider &fuzzData)
{
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    conn->HandleIncomingConnectionFromChannel(channelId, connectionName, physicalKey);
}

static void FuzzHandlePhysicalDeviceStatusChange(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<PhysicalDeviceStatus> statusList;
    for (uint8_t i = 0; i < statusCount; ++i) {
        PhysicalDeviceStatus status;
        status.physicalDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
        status.physicalDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.channelId = GenerateFuzzChannelId(fuzzData);
        status.deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.deviceModelInfo = GenerateFuzzString(fuzzData, TEST_VAL64);
        statusList.push_back(status);
    }
    conn->HandlePhysicalDeviceStatusChange(channelId, statusList);
}

static void FuzzInitialize(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    conn->Initialize();
}

static void FuzzUnsubscribeConnectionStatus(std::shared_ptr<ConnectionManager> &conn, FuzzedDataProvider &fuzzData)
{
    SubscribeId subscriptionId = fuzzData.ConsumeIntegral<SubscribeId>();
    conn->UnsubscribeConnectionStatus(subscriptionId);
}

static const ConnectionManagerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetConnection,
    FuzzGetConnectionStatus,
    FuzzOpenConnection,
    FuzzCloseConnection,
    FuzzHandleIncomingConnection,
    FuzzSubscribeConnectionStatus,
    FuzzSetMessageRouter,
    FuzzHandleChannelConnectionStatusChange,
    FuzzHandleKeepAliveReply,
    FuzzCheckResourceLimits,
    FuzzCheckIdleMonitoring,
    FuzzHandleIdleMonitorTimer,
    FuzzNotifyConnectionStatus,
    FuzzHandleChannelConnectionEstablished,
    FuzzHandleChannelConnectionClosed,
    FuzzHandleIncomingConnectionFromChannel,
    FuzzHandlePhysicalDeviceStatusChange,
    FuzzInitialize,
    FuzzUnsubscribeConnectionStatus,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(ConnectionManagerFuzzFunction);

void FuzzConnectionManager(FuzzedDataProvider &fuzzData)
{
    auto fuzzChannel = std::make_shared<FuzzCrossDeviceChannel>(fuzzData);
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(fuzzChannel);

    auto channelMgr = std::make_shared<ChannelManager>(channels);
    if (!channelMgr) {
        return;
    }

    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr,
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN });
    if (!localDeviceStatusMgr) {
        return;
    }

    auto conn = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    if (!conn) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](conn, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](conn, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzConnectionManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
