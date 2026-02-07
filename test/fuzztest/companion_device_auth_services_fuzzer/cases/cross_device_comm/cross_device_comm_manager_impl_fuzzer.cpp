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

#include "cross_device_comm_manager_impl.h"
#include "fuzz_constants.h"
#include "fuzz_cross_device_channel.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr uint32_t SIZE_64 = 64;
constexpr uint8_t UINT8_2 = 2;
constexpr uint8_t UINT8_50 = 50;
} // namespace

using CrossDeviceCommManagerImplFuzzFunction = void (*)(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData);

static void FuzzStart(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    bool result = manager.Start();
    (void)result;
}

static void FuzzIsAuthMaintainActive(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    bool isActive = manager.IsAuthMaintainActive();
    (void)isActive;
}

static void FuzzGetLocalDeviceProfile(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto profile = manager.GetLocalDeviceProfile();
    (void)profile;
}

static void FuzzGetDeviceStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto status = manager.GetDeviceStatus(deviceKey);
    (void)status;
}

static void FuzzOpenConnection(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::string outConnectionName;
    bool result = manager.OpenConnection(deviceKey, outConnectionName);
    (void)result;
}

static void FuzzCloseConnection(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    manager.CloseConnection(connectionName);
}

static void FuzzIsConnectionOpen(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    bool isOpen = manager.IsConnectionOpen(connectionName);
    (void)isOpen;
}

static void FuzzGetConnectionStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    auto status = manager.GetConnectionStatus(connectionName);
    (void)status;
}

static void FuzzSetSubscribeMode(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    uint8_t modeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_2);
    SubscribeMode mode = static_cast<SubscribeMode>(modeValue);
    manager.SetSubscribeMode(mode);
}

static void FuzzCheckOperationIntent(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto resultCallback = [](bool isValid) { (void)isValid; };
    manager.CheckOperationIntent(deviceKey, tokenId, std::move(resultCallback));
}

static void FuzzSubscribeIsAuthMaintainActive(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto subscription = manager.SubscribeIsAuthMaintainActive([](bool active) { (void)active; });
    (void)subscription;
}

static void FuzzGetAllDeviceStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto allStatus = manager.GetAllDeviceStatus();
    (void)allStatus;
}

static void FuzzSubscribeAllDeviceStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto subscription = manager.SubscribeAllDeviceStatus([](const std::vector<DeviceStatus> &status) { (void)status; });
    (void)subscription;
}

static void FuzzGetManageSubscribeTime(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto time = manager.GetManageSubscribeTime();
    (void)time;
}

static void FuzzSubscribeDeviceStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto subscription =
        manager.SubscribeDeviceStatus(deviceKey, [](const std::vector<DeviceStatus> &statusList) { (void)statusList; });
    (void)subscription;
}

static void FuzzGetLocalDeviceKeyByConnectionName(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    auto deviceKey = manager.GetLocalDeviceKeyByConnectionName(connectionName);
    (void)deviceKey;
}

static void FuzzSubscribeConnectionStatus(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    auto subscription = manager.SubscribeConnectionStatus(connectionName,
        [](const std::string &conn, ConnectionStatus status, const std::string &reason) {
            (void)conn;
            (void)status;
            (void)reason;
        });
    (void)subscription;
}

static void FuzzSubscribeIncomingConnection(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    auto subscription =
        manager.SubscribeIncomingConnection(msgType, [](const Attributes &msg, OnMessageReply &onMessageReply) {
            (void)msg;
            (void)onMessageReply;
        });
    (void)subscription;
}

static void FuzzSendMessage(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    Attributes request = GenerateFuzzAttributes(fuzzData);
    auto subscription =
        manager.SendMessage(connectionName, msgType, request, [](const Attributes &reply) { (void)reply; });
    (void)subscription;
}

static void FuzzSubscribeMessage(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    auto subscription =
        manager.SubscribeMessage(connectionName, msgType, [](const Attributes &msg, OnMessageReply &onMessageReply) {
            (void)msg;
            (void)onMessageReply;
        });
    (void)subscription;
}

static void FuzzHostGetSecureProtocolId(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto protocolId = manager.HostGetSecureProtocolId(deviceKey);
    (void)protocolId;
}

static void FuzzCompanionGetSecureProtocolId(ICrossDeviceCommManager &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto protocolId = manager.CompanionGetSecureProtocolId();
    (void)protocolId;
}

static const CrossDeviceCommManagerImplFuzzFunction g_fuzzFuncs[] = {
    FuzzStart,
    FuzzIsAuthMaintainActive,
    FuzzGetLocalDeviceProfile,
    FuzzGetDeviceStatus,
    FuzzOpenConnection,
    FuzzCloseConnection,
    FuzzIsConnectionOpen,
    FuzzGetConnectionStatus,
    FuzzSetSubscribeMode,
    FuzzCheckOperationIntent,
    FuzzSubscribeIsAuthMaintainActive,
    FuzzGetAllDeviceStatus,
    FuzzSubscribeAllDeviceStatus,
    FuzzGetManageSubscribeTime,
    FuzzSubscribeDeviceStatus,
    FuzzGetLocalDeviceKeyByConnectionName,
    FuzzSubscribeConnectionStatus,
    FuzzSubscribeIncomingConnection,
    FuzzSendMessage,
    FuzzSubscribeMessage,
    FuzzHostGetSecureProtocolId,
    FuzzCompanionGetSecureProtocolId,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CrossDeviceCommManagerImplFuzzFunction);

void FuzzCrossDeviceCommManagerImpl(FuzzedDataProvider &fuzzData)
{
    // Create a fuzz channel for CrossDeviceCommManagerImpl::Create()
    auto fuzzChannel = std::make_shared<FuzzCrossDeviceChannel>(fuzzData);
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(fuzzChannel);

    auto manager = CrossDeviceCommManagerImpl::Create({ BusinessId::DEFAULT },
        { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, channels);
    if (!manager) {
        return;
    }

    // Call Start() to initialize the manager
    manager->Start();

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](*manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](*manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzCrossDeviceCommManagerImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
