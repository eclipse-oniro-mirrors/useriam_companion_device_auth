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
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <unistd.h>

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include "companion_icon_store.h"
#include "directory_ex.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
std::string EncodeBase64(const std::vector<uint8_t> &data)
{
    std::string out((data.size() + (BASE64_GROUP_BYTES - 1)) / BASE64_GROUP_BYTES * BASE64_GROUP_SIZE, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data.data(), static_cast<int>(data.size()));
    return out;
}

std::vector<uint8_t> ReadFileAll(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

std::vector<uint8_t> MakeJsonContext(const std::string &fileName, const std::string &base64Data)
{
    std::string json = R"({"icon_file_name":")" + fileName + R"(","icon_data":")" + base64Data + R"("})";
    return std::vector<uint8_t>(json.begin(), json.end());
}

class CompanionIconStoreTest : public testing::Test {
protected:
    void SetUp() override
    {
        testDir_ = "/data/local/tmp/cda_icon_store_test_" + std::to_string(static_cast<int>(getpid()));
        ForceRemoveDirectory(testDir_);
    }

    void TearDown() override
    {
        ForceRemoveDirectory(testDir_);
    }

    std::string testDir_;
};

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

HWTEST_F(CompanionIconStoreTest, BuildIconDirectory_PerUserPath, TestSize.Level0)
{
    EXPECT_EQ(BuildIconDirectory(100), "/data/service/el1/100/useriam/companion_device_auth/icons");
    EXPECT_EQ(BuildIconDirectory(1), "/data/service/el1/1/useriam/companion_device_auth/icons");
}

HWTEST_F(CompanionIconStoreTest, Save_ToNestedNewDirectory_CreatesAndWrites, TestSize.Level0)
{
    CompanionIcon icon = { "icon.png", { 1, 2, 3, 4, 5 } };
    std::string iconDir = testDir_ + "/level1/level2/icons";
    EXPECT_EQ(SaveIconToDirectory(iconDir, icon), ResultCode::SUCCESS);

    auto readBack = ReadFileAll(iconDir + "/icon.png");
    std::vector<uint8_t> expect = { 1, 2, 3, 4, 5 };
    EXPECT_EQ(readBack, expect);
}

HWTEST_F(CompanionIconStoreTest, Save_SameName_ReplacesAtomically, TestSize.Level0)
{
    std::vector<uint8_t> first = { 1, 1, 1 };
    std::vector<uint8_t> second = { 2, 2, 2, 2, 2, 2, 2, 2 };
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "icon.png", first }), ResultCode::SUCCESS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "icon.png", second }), ResultCode::SUCCESS);

    auto readBack = ReadFileAll(testDir_ + "/icon.png");
    EXPECT_EQ(readBack, second);
    std::ifstream tmpFile(testDir_ + "/icon.png.tmp");
    EXPECT_FALSE(tmpFile.good());
}

HWTEST_F(CompanionIconStoreTest, Save_DistinctNames_Coexist, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "watch.png", { 0x0A } }), ResultCode::SUCCESS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "phone.png", { 0x0B } }), ResultCode::SUCCESS);
    EXPECT_EQ(ReadFileAll(testDir_ + "/watch.png"), std::vector<uint8_t>({ 0x0A }));
    EXPECT_EQ(ReadFileAll(testDir_ + "/phone.png"), std::vector<uint8_t>({ 0x0B }));
}

HWTEST_F(CompanionIconStoreTest, Save_EmptyData_WritesEmptyFile, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "icon.png", {} }), ResultCode::SUCCESS);
    auto readBack = ReadFileAll(testDir_ + "/icon.png");
    EXPECT_TRUE(readBack.empty());
}

HWTEST_F(CompanionIconStoreTest, Save_InvalidFileName_Fails, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "../escape.png", { 1 } }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "a/b.png", { 1 } }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "", { 1 } }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { ".", { 1 } }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "..", { 1 } }), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "icon.", { 1 } }), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Save_InvalidDirectory_Fails, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory("", { "icon.png", { 1 } }), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Delete_ExistingFile_RemovesIt, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "icon.png", { 1, 2, 3 } }), ResultCode::SUCCESS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "icon.png"), ResultCode::SUCCESS);
    std::ifstream file(testDir_ + "/icon.png");
    EXPECT_FALSE(file.good());
}

HWTEST_F(CompanionIconStoreTest, Delete_MissingFile_SucceedsIdempotent, TestSize.Level0)
{
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "absent.png"), ResultCode::SUCCESS);
}

HWTEST_F(CompanionIconStoreTest, Delete_DoesNotTouchOtherFiles, TestSize.Level0)
{
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "watch.png", { 0x0A } }), ResultCode::SUCCESS);
    EXPECT_EQ(SaveIconToDirectory(testDir_, { "phone.png", { 0x0B } }), ResultCode::SUCCESS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "watch.png"), ResultCode::SUCCESS);
    EXPECT_EQ(ReadFileAll(testDir_ + "/phone.png"), std::vector<uint8_t>({ 0x0B }));
    std::ifstream file(testDir_ + "/watch.png");
    EXPECT_FALSE(file.good());
}

HWTEST_F(CompanionIconStoreTest, Delete_InvalidName_Fails, TestSize.Level0)
{
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "../escape.png"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "a/b.png"), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, ""), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "."), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(DeleteIconFromDirectory(testDir_, "a..b"), ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionIconStoreTest, Delete_EmptyDirectory_Fails, TestSize.Level0)
{
    EXPECT_EQ(DeleteIconFromDirectory("", "icon.png"), ResultCode::INVALID_PARAMETERS);
}
} // namespace
