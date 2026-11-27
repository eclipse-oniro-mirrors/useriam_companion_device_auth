/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include "companion_icon_store.h"
#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
constexpr int32_t USER_ID = 100;
constexpr int32_t ANOTHER_USER_ID = 1;
const std::string ICON_DIR_OF_USER = "/data/service/el1/100/useriam/companion_device_auth/icons";
const std::string ICON_DIR_OF_ANOTHER_USER = "/data/service/el1/1/useriam/companion_device_auth/icons";
const std::vector<uint8_t> ICON_DATA = { 1, 2, 3, 4, 5 };

std::string EncodeBase64(const std::vector<uint8_t> &data)
{
    std::string out((data.size() + (BASE64_GROUP_BYTES - 1)) / BASE64_GROUP_BYTES * BASE64_GROUP_SIZE, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), static_cast<int>(data.size()));
    return out;
}

std::vector<uint8_t> MakeJsonContext(const std::string &fileName, const std::string &base64Data)
{
    std::string json = R"({"icon_file_name":")" + fileName + R"(","icon_data":")" + base64Data + R"("})";
    return std::vector<uint8_t>(json.begin(), json.end());
}

class CompanionIconStoreTest : public testing::Test {};

HWTEST_F(CompanionIconStoreTest, Parse_ValidContext_ReturnsFileNameAndData, TestSize.Level0)
{
    CompanionIcon icon;
    ResultCode ret = ParseIconSelectionContext(MakeJsonContext("icon.png", "aGVsbG8="), icon);
    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_EQ(icon.fileName, "icon.png");
    std::vector<uint8_t> expect = { 'h', 'e', 'l', 'l', 'o' };
    EXPECT_EQ(icon.data, expect);
}

HWTEST_F(CompanionIconStoreTest, Parse_BinaryPayload_RoundTrip, TestSize.Level0)
{
    std::vector<uint8_t> payload;
    for (size_t i = 0; i < 1024; ++i) {
        payload.push_back(static_cast<uint8_t>(i * 7 + (i >> 5)));
    }
    CompanionIcon icon;
    ResultCode ret = ParseIconSelectionContext(MakeJsonContext("a-b_9.PNG", EncodeBase64(payload)), icon);
    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_EQ(icon.fileName, "a-b_9.PNG");
    EXPECT_EQ(icon.data, payload);
}

HWTEST_F(CompanionIconStoreTest, Parse_LargeData_Passes, TestSize.Level0)
{
    constexpr size_t largeDataLength = 60 * 1024;
    std::vector<uint8_t> payload(largeDataLength, 0xAB);
    CompanionIcon icon;
    ResultCode ret = ParseIconSelectionContext(MakeJsonContext("i.png", EncodeBase64(payload)), icon);
    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_EQ(icon.data.size(), largeDataLength);
}

HWTEST_F(CompanionIconStoreTest, Parse_MaxSizeFileName_AtLimit, TestSize.Level0)
{
    std::string longName(MAX_ICON_FILE_NAME_LENGTH - 4, 'x');
    longName += ".png";
    CompanionIcon icon;
    ResultCode ret = ParseIconSelectionContext(MakeJsonContext(longName, "aGVsbG8="), icon);
    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_EQ(icon.fileName, longName);
}

HWTEST_F(CompanionIconStoreTest, Parse_ExtraFields_Tolerated, TestSize.Level0)
{
    std::string json = R"({"icon_file_name":"i.png","icon_data":"aGVsbG8=","future_field":123})";
    std::vector<uint8_t> context(json.begin(), json.end());
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(context, icon), ResultCode::SUCCESS);
}

HWTEST_F(CompanionIconStoreTest, Parse_MissingPairMember_Fails, TestSize.Level0)
{
    std::string noData = R"({"icon_file_name":"i.png"})";
    std::string noName = R"({"icon_data":"aGVsbG8="})";
    CompanionIcon icon;
    std::vector<uint8_t> ctxNoData(noData.begin(), noData.end());
    std::vector<uint8_t> ctxNoName(noName.begin(), noName.end());
    EXPECT_EQ(ParseIconSelectionContext(ctxNoData, icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(ctxNoName, icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_FieldNotString_Fails, TestSize.Level0)
{
    std::string numName = R"({"icon_file_name":123,"icon_data":"aGVsbG8="})";
    std::string numData = R"({"icon_file_name":"i.png","icon_data":456})";
    CompanionIcon icon;
    std::vector<uint8_t> ctxNumName(numName.begin(), numName.end());
    std::vector<uint8_t> ctxNumData(numData.begin(), numData.end());
    EXPECT_EQ(ParseIconSelectionContext(ctxNumName, icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(ctxNumData, icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_NotJsonObject_Fails, TestSize.Level0)
{
    CompanionIcon icon;
    std::vector<uint8_t> notJson = { 0xDE, 0xAD, 0xBE, 0xEF };
    std::string arrayJson = R"(["icon_file_name","icon_data"])";
    std::vector<uint8_t> ctxArray(arrayJson.begin(), arrayJson.end());
    std::string strJson = R"("just a string")";
    std::vector<uint8_t> ctxStr(strJson.begin(), strJson.end());
    EXPECT_EQ(ParseIconSelectionContext(notJson, icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(ctxArray, icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(ctxStr, icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_EmptyContext_Fails, TestSize.Level0)
{
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext({}, icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_InvalidBase64_Fails, TestSize.Level0)
{
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("i.png", "aGVsbG8"), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("i.png", "aGVs*g8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("i.png", "aG=sbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("i.png", "aGVsbG8x="), icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_OversizeContext_Fails, TestSize.Level0)
{
    std::vector<uint8_t> context(MAX_ARRAY_LENGTH + 1, 'x');
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(context, icon), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_BadFileName_Fails, TestSize.Level0)
{
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("..", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext(".", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("a/b", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("a b.png", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    std::string chineseName = "手表图标";
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext(chineseName, "aGVsbG8="), icon),
        ResultCode::INVALID_PARAMETERS);
    std::string overLenName(MAX_ICON_FILE_NAME_LENGTH + 1, 'x');
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext(overLenName, "aGVsbG8="), icon),
        ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_FileNameBadDotLayout_Fails, TestSize.Level0)
{
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext(".png", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("png.", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext(".hidden", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("a..b", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("a.b.c.", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("watch", "aGVsbG8="), icon), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("my.watch.png", "aGVsbG8="), icon),
        ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Parse_FileNameCharset_Passes, TestSize.Level0)
{
    CompanionIcon icon;
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("watch-1_2.png", "aGVsbG8="), icon), ResultCode::SUCCESS);
    EXPECT_EQ(icon.fileName, "watch-1_2.png");
    EXPECT_EQ(ParseIconSelectionContext(MakeJsonContext("a-b_9.PNG", "aGVsbG8="), icon), ResultCode::SUCCESS);
    EXPECT_EQ(icon.fileName, "a-b_9.PNG");
}

// The store owns naming and the per-user directory and hands the absolute path to the storage
// adapter, which owns the file system.
HWTEST_F(CompanionIconStoreTest, Save_HandsIconOfHostUserToStorageAdapter, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_EQ(SaveIcon(USER_ID, { "watch.png", ICON_DATA }), ResultCode::SUCCESS);
    EXPECT_EQ(SaveIcon(ANOTHER_USER_ID, { "watch.png", ICON_DATA }), ResultCode::SUCCESS);

    EXPECT_EQ(guard.GetFileStorageAdapter().GetSavedFiles(),
        std::vector<MockFileStorageAdapter::SavedFile>(
            { { ICON_DIR_OF_USER, "watch.png", ICON_DATA }, { ICON_DIR_OF_ANOTHER_USER, "watch.png", ICON_DATA } }));
}

// A storage failure comes back to the caller, which decides what it means for its own flow.
HWTEST_F(CompanionIconStoreTest, Save_StorageFailure_IsPropagated, TestSize.Level0)
{
    MockGuard guard;
    guard.GetFileStorageAdapter().SetSaveResult(ResultCode::GENERAL_ERROR);

    EXPECT_EQ(SaveIcon(USER_ID, { "watch.png", ICON_DATA }), ResultCode::GENERAL_ERROR);
    ASSERT_EQ(guard.GetFileStorageAdapter().GetSavedFiles().size(), 1u);
}

// A name that could escape the icon directory, or no host user at all, is refused before storage.
HWTEST_F(CompanionIconStoreTest, Save_InvalidNameOrUser_NeverReachesStorage, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_EQ(SaveIcon(USER_ID, { "../escape.png", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(USER_ID, { "a/b.png", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(USER_ID, { "", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(USER_ID, { ".", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(USER_ID, { "..", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(USER_ID, { "icon.", ICON_DATA }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIcon(INVALID_USER_ID, { "icon.png", ICON_DATA }), ResultCode::INVALID_PARAMETERS);

    EXPECT_TRUE(guard.GetFileStorageAdapter().GetSavedFiles().empty());
}

HWTEST_F(CompanionIconStoreTest, Delete_HandsIconOfHostUserToStorageAdapter, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_EQ(DeleteIcon(USER_ID, "watch.png"), ResultCode::SUCCESS);

    EXPECT_EQ(guard.GetFileStorageAdapter().GetDeletedFiles(),
        std::vector<MockFileStorageAdapter::DeletedFile>({ { ICON_DIR_OF_USER, "watch.png" } }));
}

HWTEST_F(CompanionIconStoreTest, Delete_StorageFailure_IsPropagated, TestSize.Level0)
{
    MockGuard guard;
    guard.GetFileStorageAdapter().SetDeleteResult(ResultCode::GENERAL_ERROR);

    EXPECT_EQ(DeleteIcon(USER_ID, "watch.png"), ResultCode::GENERAL_ERROR);
    ASSERT_EQ(guard.GetFileStorageAdapter().GetDeletedFiles().size(), 1u);
}

HWTEST_F(CompanionIconStoreTest, Delete_InvalidNameOrUser_NeverReachesStorage, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_EQ(DeleteIcon(USER_ID, "../escape.png"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIcon(USER_ID, "a/b.png"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIcon(USER_ID, ""), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIcon(USER_ID, "."), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIcon(USER_ID, "a..b"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIcon(INVALID_USER_ID, "icon.png"), ResultCode::INVALID_PARAMETERS);

    EXPECT_TRUE(guard.GetFileStorageAdapter().GetDeletedFiles().empty());
}
} // namespace
