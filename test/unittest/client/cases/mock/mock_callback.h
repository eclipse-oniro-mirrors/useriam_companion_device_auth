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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H

#include <gmock/gmock.h>

#include "iavailable_device_status_callback.h"
#include "icontinuous_auth_status_callback.h"
#include "idevice_select_callback.h"
#include "itemplate_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Mock implementation of IDeviceSelectCallback for testing.
 */
class MockDeviceSelectCallback : public IDeviceSelectCallback {
public:
    virtual ~MockDeviceSelectCallback() = default;
    MOCK_METHOD(void, OnDeviceSelect,
        (int32_t selectPurpose, const std::shared_ptr<SetDeviceSelectResultCallback> &callback), (override));
};

/**
 * @brief Mock implementation of ITemplateStatusCallback for testing.
 */
class MockTemplateStatusCallback : public ITemplateStatusCallback {
public:
    virtual ~MockTemplateStatusCallback() = default;
    MockTemplateStatusCallback() = default;
    explicit MockTemplateStatusCallback(int32_t userId) : userId_(userId)
    {
    }

    MOCK_METHOD(void, OnTemplateStatusChange, (const std::vector<ClientTemplateStatus> templateStatusList), (override));

    int32_t GetUserId() override
    {
        return userId_;
    }

private:
    int32_t userId_ = 0;
};

/**
 * @brief Mock implementation of IAvailableDeviceStatusCallback for testing.
 */
class MockAvailableDeviceStatusCallback : public IAvailableDeviceStatusCallback {
public:
    virtual ~MockAvailableDeviceStatusCallback() = default;
    MockAvailableDeviceStatusCallback() = default;
    explicit MockAvailableDeviceStatusCallback(int32_t userId) : userId_(userId)
    {
    }

    MOCK_METHOD(void, OnAvailableDeviceStatusChange, (const std::vector<ClientDeviceStatus> deviceStatusList),
        (override));

    int32_t GetUserId() override
    {
        return userId_;
    }

private:
    int32_t userId_ = 0;
};

/**
 * @brief Mock implementation of IContinuousAuthStatusCallback for testing.
 */
class MockContinuousAuthStatusCallback : public IContinuousAuthStatusCallback {
public:
    virtual ~MockContinuousAuthStatusCallback() = default;
    MockContinuousAuthStatusCallback() = default;
    MockContinuousAuthStatusCallback(int32_t userId, const std::optional<uint64_t> &templateId)
        : userId_(userId),
          templateId_(templateId)
    {
    }

    MOCK_METHOD(void, OnContinuousAuthStatusChange, (const bool isAuthPassed, std::optional<int32_t> remainingTime),
        (override));

    int32_t GetUserId() override
    {
        return userId_;
    }

    std::optional<uint64_t> GetTemplateId() override
    {
        return templateId_;
    }

private:
    int32_t userId_ = 0;
    std::optional<uint64_t> templateId_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_CALLBACK_H
