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

#ifndef COMPANION_DEVICE_AUTH_TEST_MOCK_USAGE_EXAMPLE_H
#define COMPANION_DEVICE_AUTH_TEST_MOCK_USAGE_EXAMPLE_H

/**
 * Mock Classes Optimization Guide
 *
 * This document demonstrates how to use the improved MockRequestFactory,
 * MockRequestManager, and MockIRequest classes for unit and fuzz testing.
 *
 * Key Improvements:
 * 1. MockIRequest - Fully configurable mock request with controllable return values
 * 2. MockRequestFactory - Creates mock requests with automatic ID assignment
 * 3. MockRequestManager - Manages requests with configurable behaviors
 *
 * Usage Examples:
 * ==============
 */

/**
 * Example 1: Basic Mock Request Usage
 *
 * auto mockRequest = std::make_shared<MockIRequest>(
 *     RequestType::HOST_ADD_COMPANION_REQUEST,
 *     1,  // requestId
 *     0   // scheduleId
 * );
 *
 * // Configure the mock request
 * mockRequest->SetMaxConcurrency(2);
 * mockRequest->SetShouldCancel(true);
 * mockRequest->SetDescription("CustomRequest");
 *
 * // Use in tests
 * ASSERT_EQ(mockRequest->GetRequestId(), 1);
 * ASSERT_EQ(mockRequest->GetRequestType(), RequestType::HOST_ADD_COMPANION_REQUEST);
 */

/**
 * Example 2: Mock Factory Integration
 *
 * auto factory = std::make_shared<MockRequestFactory>();
 *
 * // Configure factory behavior
 * factory->SetDefaultMaxConcurrency(3);
 * factory->SetShouldReturnNull(false);
 *
 * // Create requests
 * auto request1 = factory->CreateHostAddCompanionRequest(
 *     scheduleId, fwkMsg, tokenId, callback
 * );
 *
 * // Inspect created request
 * auto lastRequest = factory->GetLastCreatedRequest();
 * ASSERT_EQ(factory->GetRequestCount(), 1);
 *
 * // Test null case
 * factory->SetShouldReturnNull(true);
 * auto nullRequest = factory->CreateHostTokenAuthRequest(
 *     scheduleId, fwkMsg, userId, templateId, callback
 * );
 * ASSERT_EQ(nullRequest, nullptr);
 */

/**
 * Example 3: Mock Manager with Request Storage
 *
 * auto manager = std::make_shared<MockRequestManager>();
 * auto mockRequest = std::make_shared<MockIRequest>(
 *     RequestType::HOST_TOKEN_AUTH_REQUEST, 42, 1
 * );
 *
 * // Start a request
 * ASSERT_TRUE(manager->Start(mockRequest));
 * ASSERT_EQ(manager->GetRequestCount(), 1);
 *
 * // Retrieve request
 * auto retrieved = manager->Get(42);
 * ASSERT_EQ(retrieved->GetRequestId(), 42);
 *
 * // Cancel request
 * ASSERT_TRUE(manager->Cancel(42));
 *
 * // Test failure cases
 * manager->SetShouldCancelSucceed(false);
 * ASSERT_FALSE(manager->Cancel(99));
 */

/**
 * Example 4: Fuzz Testing Integration
 *
 * void FuzzRequestFactoryWithMocks(FuzzedDataProvider &fuzzData)
 * {
 *     auto factory = std::make_shared<MockRequestFactory>();
 *     auto manager = std::make_shared<MockRequestManager>();
 *
 *     uint32_t operations = fuzzData.ConsumeIntegralInRange<uint32_t>(0, 100);
 *
 *     for (uint32_t i = 0; i < operations; ++i) {
 *         uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 2);
 *
 *         switch (operation) {
 *             case 0: {
 *                 // Create request
 *                 auto request = factory->CreateHostAddCompanionRequest(
 *                     fuzzData.ConsumeIntegral<uint64_t>(),
 *                     std::vector<uint8_t>(), 0, nullptr
 *                 );
 *                 if (request) {
 *                     manager->Start(request);
 *                 }
 *                 break;
 *             }
 *             case 1: {
 *                 // Cancel request
 *                 uint32_t requestId = fuzzData.ConsumeIntegral<uint32_t>();
 *                 (void)manager->Cancel(requestId);
 *                 break;
 *             }
 *             case 2: {
 *                 // Get request
 *                 uint32_t requestId = fuzzData.ConsumeIntegral<uint32_t>();
 *                 auto req = manager->Get(requestId);
 *                 if (req) {
 *                     (void)req->GetRequestType();
 *                 }
 *                 break;
 *             }
 *         }
 *     }
 * }
 */

/**
 * Example 5: Thread-Safe Operations
 *
 * auto manager = std::make_shared<MockRequestManager>();
 *
 * // Multiple threads can safely access the manager
 * std::thread t1([&manager]() {
 *     auto req = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST, 1, 0);
 *     manager->Start(req);
 * });
 *
 * std::thread t2([&manager]() {
 *     auto retrieved = manager->Get(1);
 *     if (retrieved) {
 *         (void)retrieved->GetRequestId();
 *     }
 * });
 *
 * t1.join();
 * t2.join();
 */

/**
 * Configuration Methods Summary:
 * ============================
 *
 * MockIRequest:
 *   - SetRequestType(RequestType)
 *   - SetRequestId(RequestId)
 *   - SetScheduleId(ScheduleId)
 *   - SetDescription(const char*)
 *   - SetMaxConcurrency(uint32_t)
 *   - SetShouldCancel(bool)
 *   - SetPeerDeviceKey(const std::optional<DeviceKey>&)
 *   - SetCancelReturnValue(bool)
 *
 * MockRequestFactory:
 *   - SetShouldReturnNull(bool)
 *   - SetDefaultRequestType(RequestType)
 *   - SetDefaultMaxConcurrency(uint32_t)
 *   - GetLastCreatedRequest()
 *   - GetRequestCount()
 *
 * MockRequestManager:
 *   - SetShouldStartSucceed(bool)
 *   - SetShouldCancelSucceed(bool)
 *   - SetShouldRemoveSucceed(bool)
 *   - SetDefaultMockRequest(std::shared_ptr<MockIRequest>)
 *   - GetRequestCount()
 *   - ClearAllRequests()
 *   - GetAllRequests()
 */

#endif // COMPANION_DEVICE_AUTH_TEST_MOCK_USAGE_EXAMPLE_H
