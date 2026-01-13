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

#include "cross_device_common.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "soft_bus_channel.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL64 = 64;
}

using SoftBusChannelFuzzFunction = void (*)(std::shared_ptr<SoftBusChannel> &, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetChannelId
    (void)channel->GetChannelId();
}

static void FuzzOp1(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetCompanionSecureProtocolId
    (void)channel->GetCompanionSecureProtocolId();
}

static void FuzzOp2(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetAuthMaintainActive
    (void)channel->GetAuthMaintainActive();
}

static void FuzzOp3(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Start
    channel->Start();
}

static void FuzzOp4(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OpenConnection
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    channel->OpenConnection(connectionName, physicalKey);
}

static void FuzzOp5(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test CloseConnection
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    channel->CloseConnection(connectionName);
}

static void FuzzOp6(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SendMessage
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::vector<uint8_t> rawMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    channel->SendMessage(connectionName, rawMsg);
}

static void FuzzOp7(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test CheckOperationIntent
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto callback = [](bool confirmed) { (void)confirmed; };
    channel->CheckOperationIntent(deviceKey, tokenId, std::move(callback));
}

static void FuzzOp8(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RequiresDisconnectNotification
    (void)channel->RequiresDisconnectNotification();
}

static void FuzzOp9(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OnRemoteDisconnect
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::string reason = GenerateFuzzString(fuzzData, 128);
    channel->OnRemoteDisconnect(connectionName, reason);
}

static void FuzzOp10(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetLocalPhysicalDeviceKey
    (void)channel->GetLocalPhysicalDeviceKey();
}

static void FuzzOp11(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetAllPhysicalDevices
    (void)channel->GetAllPhysicalDevices();
}

static void FuzzOp12(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribePhysicalDeviceStatus
    auto subscription =
        channel->SubscribePhysicalDeviceStatus([](const std::vector<PhysicalDeviceStatus> &deviceStatus) {
            // Callback - intentionally does nothing
            (void)deviceStatus;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp13(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeRawMessage
    auto subscription =
        channel->SubscribeRawMessage([](const std::string &connectionName, const std::vector<uint8_t> &message) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)message;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp14(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeConnectionStatus
    auto subscription = channel->SubscribeConnectionStatus(
        [](const std::string &connectionName, ConnectionStatus status, const std::string &reason) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)status;
            (void)reason;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp15(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeIncomingConnection
    auto subscription = channel->SubscribeIncomingConnection(
        [](const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)physicalDeviceKey;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp16(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeAuthMaintainActive
    auto subscription = channel->SubscribeAuthMaintainActive([](bool isActive) {
        // Callback - intentionally does nothing
        (void)isActive;
    });
    // Subscription will be automatically cleaned up
}

static void FuzzOp17(std::shared_ptr<SoftBusChannel> &channel, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test ConvertToConnectionStatus (inline function from cross_device_common.h)
    (void)channel; // Unused in this test
    bool isConnected = fuzzData.ConsumeBool();
    std::string reason = GenerateFuzzString(fuzzData, 128);
    ConnectionStatus status = ConvertToConnectionStatus(isConnected, reason);
    (void)status;
}

static const SoftBusChannelFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5, FuzzOp6,
    FuzzOp7, FuzzOp8, FuzzOp9, FuzzOp10, FuzzOp11, FuzzOp12, FuzzOp13, FuzzOp14, FuzzOp15, FuzzOp16, FuzzOp17 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SoftBusChannelFuzzFunction);

void FuzzSoftBusChannel(FuzzedDataProvider &fuzzData)
{
    // Create SoftBusChannel instance
    auto channel = SoftBusChannel::Create();
    if (!channel) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](channel, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

FUZZ_REGISTER(SoftBusChannel)
