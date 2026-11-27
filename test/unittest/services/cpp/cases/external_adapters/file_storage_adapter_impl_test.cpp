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

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "file_storage_adapter_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

// The real adapter writes to the file system, which a unit test never does. Only the boundary that
// returns before any file is touched is pinned here; the callers' use of the adapter is covered
// with the mock.
namespace {
const std::vector<uint8_t> FILE_CONTENT = { 1, 2, 3, 4, 5 };
// Beneath a character device: no directory can ever be created there, so a broken name check
// could not turn these cases into a real write either.
constexpr const char *UNCREATABLE_DIR = "/dev/null/icons";

HWTEST(FileStorageAdapterImplTest, Create_ReturnsInstance, TestSize.Level0)
{
    EXPECT_NE(FileStorageAdapterImpl::Create(), nullptr);
}

// A file name is one path segment: it can neither be empty nor climb out of the directory.
HWTEST(FileStorageAdapterImplTest, Save_InvalidFileNameOrDirectory_Fails, TestSize.Level0)
{
    auto adapter = FileStorageAdapterImpl::Create();
    ASSERT_NE(adapter, nullptr);

    EXPECT_EQ(adapter->SaveFile(UNCREATABLE_DIR, "", FILE_CONTENT), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->SaveFile(UNCREATABLE_DIR, ".", FILE_CONTENT), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->SaveFile(UNCREATABLE_DIR, "..", FILE_CONTENT), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->SaveFile(UNCREATABLE_DIR, "a/b", FILE_CONTENT), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->SaveFile("", "data.bin", FILE_CONTENT), ResultCode::INVALID_PARAMETERS);
}

HWTEST(FileStorageAdapterImplTest, Delete_InvalidFileNameOrDirectory_Fails, TestSize.Level0)
{
    auto adapter = FileStorageAdapterImpl::Create();
    ASSERT_NE(adapter, nullptr);

    EXPECT_EQ(adapter->DeleteFile(UNCREATABLE_DIR, ""), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->DeleteFile(UNCREATABLE_DIR, "."), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->DeleteFile(UNCREATABLE_DIR, ".."), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->DeleteFile(UNCREATABLE_DIR, "a/b"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(adapter->DeleteFile("", "data.bin"), ResultCode::INVALID_PARAMETERS);
}
} // namespace
