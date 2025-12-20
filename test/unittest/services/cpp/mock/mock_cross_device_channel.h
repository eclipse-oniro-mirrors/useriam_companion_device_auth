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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_CHANNEL_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_CHANNEL_H

#include <gmock/gmock.h>

#include "icross_device_channel.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockCrossDeviceChannel : public ICrossDeviceChannel {
public:
    MOCK_METHOD(bool, Start, (), (override));

    MOCK_METHOD(ChannelId, GetChannelId, (), (const, override));
    MOCK_METHOD(PhysicalDeviceKey, GetLocalPhysicalDeviceKey, (), (const, override));

    MOCK_METHOD(bool, OpenConnection, (const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey),
        (override));
    MOCK_METHOD(void, CloseConnection, (const std::string &connectionName), (override));
    MOCK_METHOD(bool, SendMessage, (const std::string &connectionName, const std::vector<uint8_t> &rawMsg), (override));

    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribePhysicalDeviceStatus,
        (OnPhysicalDeviceStatusChange && callback), (override));
    MOCK_METHOD(std::vector<PhysicalDeviceStatus>, GetAllPhysicalDevices, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeRawMessage, (OnRawMessage && callback), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeConnectionStatus, (OnConnectionStatusChange && callback),
        (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeIncomingConnection, (OnIncomingConnection && callback),
        (override));

    MOCK_METHOD(bool, GetAuthMaintainActive, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeAuthMaintainActive, (OnAuthMaintainActiveChange && callback),
        (override));

    MOCK_METHOD(SecureProtocolId, GetcompanionSecureProtocolId, (), (const, override));

    MOCK_METHOD(bool, CheckOperationIntent,
        (const DeviceKey &deviceKey, uint32_t tokenId, OnCheckOperationIntentResult &&resultCallback), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_CHANNEL_H
