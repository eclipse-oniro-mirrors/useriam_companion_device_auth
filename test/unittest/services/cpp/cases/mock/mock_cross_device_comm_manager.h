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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_COMM_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_COMM_MANAGER_H

#include <gmock/gmock.h>

#include "cross_device_comm_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockCrossDeviceCommManager : public ICrossDeviceCommManager {
public:
    MOCK_METHOD(bool, Start, (), (override));

    MOCK_METHOD(bool, IsAuthMaintainActive, (), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeIsAuthMaintainActive, (std::function<void(bool)> && callback),
        (override));
    MOCK_METHOD(LocalDeviceProfile, GetLocalDeviceProfile, (), (override));

    MOCK_METHOD(std::optional<DeviceStatus>, GetDeviceStatus, (const DeviceKey &deviceKey), (override));
    MOCK_METHOD(std::vector<DeviceStatus>, GetAllDeviceStatus, (), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeAllDeviceStatus, (OnDeviceStatusChange && onDeviceStatusChange),
        (override));

    MOCK_METHOD(void, SetSubscribeMode, (SubscribeMode subscribeMode), (override));
    MOCK_METHOD(std::optional<int64_t>, GetManageSubscribeTime, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeDeviceStatus,
        (const DeviceKey &deviceKey, OnDeviceStatusChange &&onDeviceStatusChange), (override));

    MOCK_METHOD(bool, OpenConnection, (const DeviceKey &deviceKey, std::string &outConnectionName), (override));
    MOCK_METHOD(void, CloseConnection, (const std::string &connectionName), (override));
    MOCK_METHOD(bool, IsConnectionOpen, (const std::string &connectionName), (override));
    MOCK_METHOD(ConnectionStatus, GetConnectionStatus, (const std::string &connectionName), (override));
    MOCK_METHOD(std::optional<DeviceKey>, GetLocalDeviceKeyByConnectionName, (const std::string &connectionName),
        (override));

    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeConnectionStatus,
        (const std::string &connectionName, OnConnectionStatusChange &&onConnectionStatusChange), (override));

    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeIncomingConnection,
        (MessageType msgType, OnMessage &&onMessage), (override));
    MOCK_METHOD(bool, SendMessage,
        (const std::string &connectionName, MessageType msgType, Attributes &request, OnMessageReply &&onMessageReply),
        (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeMessage,
        (const std::string &connectionName, MessageType msgType, OnMessage &&onMessage), (override));

    MOCK_METHOD(bool, CheckOperationIntent,
        (const DeviceKey &deviceKey, uint32_t tokenId, OnCheckOperationIntentResult &&resultCallback), (override));
    MOCK_METHOD(std::optional<SecureProtocolId>, HostGetSecureProtocolId, (const DeviceKey &companionDeviceKey),
        (override));
    MOCK_METHOD(SecureProtocolId, CompanionGetSecureProtocolId, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_CROSS_DEVICE_COMM_MANAGER_H
