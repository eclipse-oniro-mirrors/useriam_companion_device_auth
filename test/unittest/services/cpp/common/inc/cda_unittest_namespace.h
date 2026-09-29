/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CDA_TEST_NAMESPACE_H
#define CDA_TEST_NAMESPACE_H

// Test-only namespace shortcuts
// Use these for cleaner test code

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Forward declarations for mock types
class MockGuard;
class MockTimeKeeper;
class MockUserAuthAdapter;
class MockIdmAdapter;
class MockDriverManagerAdapter;
class MockSAManagerAdapter;
class MockSystemParamManager;
class MockUserKeyManager;
class MockCrossDeviceCommManager;
class MockSecurityAgent;
class MockCompanionManager;
class MockHostBindingManager;
class MockMiscManager;
class MockRequestManager;
class MockRequestFactory;

// Common type forward declarations
using ResultCode = uint32_t;
class Subscription;
using DeviceKey = std::string;
using UserId = int32_t;
using TemplateId = uint64_t;
using RequestId = std::string;
using ScheduleId = uint64_t;
using SubscribeId = uint32_t;
using SteadyTimeMs = uint64_t;
using SystemTimeMs = uint64_t;

} // namespace CompanionDeviceAuth

// Base library namespace shortcut
namespace CDA = CompanionDeviceAuth;

// MockGuard shortcut
using MockGuard = CompanionDeviceAuth::MockGuard;

// Common mock type shortcuts
using MockTimeKeeper = CompanionDeviceAuth::MockTimeKeeper;
using MockUserAuthAdapter = CompanionDeviceAuth::MockUserAuthAdapter;
using MockIdmAdapter = CompanionDeviceAuth::MockIdmAdapter;
using MockDriverManagerAdapter = CompanionDeviceAuth::MockDriverManagerAdapter;
using MockSAManagerAdapter = CompanionDeviceAuth::MockSAManagerAdapter;
using MockSystemParamManager = CompanionDeviceAuth::MockSystemParamManager;
using MockUserKeyManager = CompanionDeviceAuth::MockUserKeyManager;
using MockCrossDeviceCommManager = CompanionDeviceAuth::MockCrossDeviceCommManager;
using MockSecurityAgent = CompanionDeviceAuth::MockSecurityAgent;
using MockCompanionManager = CompanionDeviceAuth::MockCompanionManager;
using MockHostBindingManager = CompanionDeviceAuth::MockHostBindingManager;
using MockMiscManager = CompanionDeviceAuth::MockMiscManager;
using MockRequestManager = CompanionDeviceAuth::MockRequestManager;
using MockRequestFactory = CompanionDeviceAuth::MockRequestFactory;

// Common type shortcuts
using ResultCode = CompanionDeviceAuth::ResultCode;
using Subscription = CompanionDeviceAuth::Subscription;
using DeviceKey = CompanionDeviceAuth::DeviceKey;
using UserId = CompanionDeviceAuth::UserId;
using TemplateId = CompanionDeviceAuth::TemplateId;
using RequestId = CompanionDeviceAuth::RequestId;
using ScheduleId = CompanionDeviceAuth::ScheduleId;
using SubscribeId = CompanionDeviceAuth::SubscribeId;
using SteadyTimeMs = CompanionDeviceAuth::SteadyTimeMs;
using SystemTimeMs = CompanionDeviceAuth::SystemTimeMs;

} // namespace UserIam
} // namespace OHOS

#endif // CDA_TEST_NAMESPACE_H
