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

#include <memory>

#include "ipc_object_stub.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "adapter_manager.h"
#include "common_defines.h"
#include "misc_manager_impl.h"
#include "mock_time_keeper.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class FakeRemoteObject : public IPCObjectStub {
public:
    FakeRemoteObject() : IPCObjectStub(u"FakeRemoteObject")
    {
    }
    ~FakeRemoteObject() override = default;
};

class MockIIpcDeviceSelectCallback : public IIpcDeviceSelectCallback {
public:
    MOCK_METHOD(ErrCode, OnDeviceSelect,
        (int32_t selectPurpose, const sptr<IIpcSetDeviceSelectResultCallback> &callback), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

class MiscManagerImplTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }
};

HWTEST_F(MiscManagerImplTest, Create_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(MiscManagerImplTest, GetNextGlobalId_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    // Test that IDs are monotonically increasing
    // Note: IDs start from a random value to avoid conflicts, not from 1
    uint64_t id1 = manager->GetNextGlobalId();
    uint64_t id2 = manager->GetNextGlobalId();
    uint64_t id3 = manager->GetNextGlobalId();

    EXPECT_LT(id1, id2);
    EXPECT_LT(id2, id3);
    EXPECT_EQ(id1 + 1, id2);
    EXPECT_EQ(id2 + 1, id3);
}

HWTEST_F(MiscManagerImplTest, GetNextGlobalId_002, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    // Test that IDs are monotonically increasing
    uint64_t prevId = 0;
    for (int i = 0; i < 100; i++) {
        uint64_t id = manager->GetNextGlobalId();
        ASSERT_GT(id, prevId);
        prevId = id;
    }
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool result = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_002, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    bool result = manager->SetDeviceSelectCallback(tokenId, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_003, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(nullptr));

    bool result = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, SetDeviceSelectCallback_004, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback1 = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    sptr<MockIIpcDeviceSelectCallback> callback2 = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback1);
    ASSERT_NE(nullptr, callback2);

    sptr<FakeRemoteObject> remoteObj1 = sptr<FakeRemoteObject>::MakeSptr();
    sptr<FakeRemoteObject> remoteObj2 = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj1);
    ASSERT_NE(nullptr, remoteObj2);

    EXPECT_CALL(*callback1, AsObject()).WillOnce(Return(remoteObj1));
    EXPECT_CALL(*callback2, AsObject()).WillOnce(Return(remoteObj2));

    bool result1 = manager->SetDeviceSelectCallback(tokenId, callback1);
    EXPECT_TRUE(result1);

    bool result2 = manager->SetDeviceSelectCallback(tokenId, callback2);
    EXPECT_TRUE(result2);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;

    bool callbackCalled = false;
    DeviceSelectResultHandler resultHandler = [&callbackCalled](
                                                  const std::vector<DeviceKey> &devices) { callbackCalled = true; };

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_002, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_003, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    bool callbackCalled = false;
    DeviceSelectResultHandler resultHandler = [&callbackCalled](
                                                  const std::vector<DeviceKey> &devices) { callbackCalled = true; };

    EXPECT_CALL(*callback, OnDeviceSelect(_, _)).WillOnce(Return(ERR_OK));

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, GetDeviceDeviceSelectResult_004, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    DeviceSelectResultHandler resultHandler = [](const std::vector<DeviceKey> &devices) {};

    EXPECT_CALL(*callback, OnDeviceSelect(_, _)).WillOnce(Return(ERR_INVALID_VALUE));

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, ClearDeviceSelectCallback_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    sptr<MockIIpcDeviceSelectCallback> callback = sptr<MockIIpcDeviceSelectCallback>::MakeSptr();
    ASSERT_NE(nullptr, callback);

    sptr<FakeRemoteObject> remoteObj = sptr<FakeRemoteObject>::MakeSptr();
    ASSERT_NE(nullptr, remoteObj);

    EXPECT_CALL(*callback, AsObject()).WillOnce(Return(remoteObj));

    bool setResult = manager->SetDeviceSelectCallback(tokenId, callback);
    EXPECT_TRUE(setResult);

    manager->ClearDeviceSelectCallback(tokenId);

    SelectPurpose selectPurpose = SelectPurpose::SELECT_ADD_DEVICE;
    DeviceSelectResultHandler resultHandler = [](const std::vector<DeviceKey> &devices) {};

    bool result = manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, ClearDeviceSelectCallback_002, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    uint32_t tokenId = 12345;
    manager->ClearDeviceSelectCallback(tokenId);
}

HWTEST_F(MiscManagerImplTest, GetLocalUdid_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto udid = manager->GetLocalUdid();
    EXPECT_TRUE(udid.has_value());
}

HWTEST_F(MiscManagerImplTest, CheckBusinessIds_001, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<BusinessId> businessIds = { BusinessId::DEFAULT };
    bool result = manager->CheckBusinessIds(businessIds);
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, CheckBusinessIds_002, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<BusinessId> businessIds = { BusinessId::DEFAULT, BusinessId::DEFAULT, BusinessId::DEFAULT };
    bool result = manager->CheckBusinessIds(businessIds);
    EXPECT_TRUE(result);
}

HWTEST_F(MiscManagerImplTest, CheckBusinessIds_003, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<BusinessId> businessIds = { static_cast<BusinessId>(2) };
    bool result = manager->CheckBusinessIds(businessIds);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, CheckBusinessIds_004, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<BusinessId> businessIds = { BusinessId::DEFAULT, static_cast<BusinessId>(2) };
    bool result = manager->CheckBusinessIds(businessIds);
    EXPECT_FALSE(result);
}

HWTEST_F(MiscManagerImplTest, CheckBusinessIds_005, TestSize.Level0)
{
    auto manager = MiscManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<BusinessId> businessIds;
    bool result = manager->CheckBusinessIds(businessIds);
    EXPECT_TRUE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
