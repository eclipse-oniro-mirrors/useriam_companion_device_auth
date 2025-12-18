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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_MISC_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_MISC_MANAGER_H

#include <gmock/gmock.h>

#include "misc_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockMiscManager : public IMiscManager {
public:
    MOCK_METHOD(int32_t, GetNextGlobalId, (), (override));
    MOCK_METHOD(bool, SetDeviceSelectCallback,
        (uint32_t tokenId, const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback), (override));
    MOCK_METHOD(bool, GetDeviceDeviceSelectResult,
        (uint32_t tokenId, SelectPurpose selectPurpose, DeviceSelectResultHandler &&resultHandler), (override));
    MOCK_METHOD(void, ClearDeviceSelectCallback, (uint32_t tokenId), (override));
    MOCK_METHOD(std::optional<std::string>, GetLocalUdid, (), (override));
    MOCK_METHOD(uint32_t, GetAccessTokenId, (IPCObjectStub & stub), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_MISC_MANAGER_H
