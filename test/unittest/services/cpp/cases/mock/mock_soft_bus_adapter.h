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

#ifndef MOCK_SOFT_BUS_ADAPTER_H
#define MOCK_SOFT_BUS_ADAPTER_H

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "soft_bus_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockSoftBusAdapter : public ISoftBusAdapter {
public:
    MOCK_METHOD(void, RegisterCallback, (std::shared_ptr<ISoftBusSocketCallback>), (override));
    MOCK_METHOD(std::optional<int32_t>, CreateServerSocket, (), (override));
    MOCK_METHOD(std::optional<int32_t>, CreateClientSocket, (const std::string &), (override));
    MOCK_METHOD(bool, SendBytes, (int32_t, const std::vector<uint8_t> &), (override));
    MOCK_METHOD(void, ShutdownSocket, (int32_t), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_SOFT_BUS_ADAPTER_H
