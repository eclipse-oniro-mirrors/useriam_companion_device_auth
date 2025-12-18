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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SYSTEM_PARAM_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SYSTEM_PARAM_MANAGER_H

#include <gmock/gmock.h>

#include "system_param_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockSystemParamManager : public ISystemParamManager {
public:
    MOCK_METHOD(std::string, GetParam, (const std::string &key, const std::string &defaultValue), (override));
    MOCK_METHOD(void, SetParam, (const std::string &key, const std::string &value), (override));
    MOCK_METHOD(void, SetParamTwice, (const std::string &key, const std::string &value1, const std::string &value2),
        (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, WatchParam, (const std::string &key, SystemParamCallback &&callback),
        (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_SYSTEM_PARAM_MANAGER_H
