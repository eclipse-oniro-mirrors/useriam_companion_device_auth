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

#include "companion_icon_store.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "cda_json_helper.h"
#include "cda_scope_guard.h"
#include "directory_ex.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "service_common.h"
#include "unique_fd.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION_ICON_STORE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr const char *ICON_FILE_NAME_KEY = "icon_file_name";
constexpr const char *ICON_DATA_KEY = "icon_data";
constexpr const char *ICON_TMP_SUFFIX = ".tmp";
constexpr const char ICON_PATH_SEPARATOR = '/';

std::string g_iconStoreRoot = ICON_STORE_ROOT;

bool IsAllowedIconNameChar(char c)
{
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_';
}

bool IsValidIconFileName(const std::string &fileName)
{
    if (fileName.empty() || fileName.size() > MAX_ICON_FILE_NAME_LENGTH) {
        return false;
    }
    size_t firstDot = fileName.find('.');
    size_t lastDot = fileName.rfind('.');
    if (firstDot == std::string::npos || firstDot != lastDot) {
        return false;
    }
    size_t nameLength = firstDot;
    size_t extLength = fileName.size() - firstDot - 1;
    if (nameLength == 0 || extLength == 0) {
        return false;
    }
    return std::all_of(fileName.begin(), fileName.begin() + nameLength, IsAllowedIconNameChar) &&
        std::all_of(fileName.begin() + nameLength + 1, fileName.end(), IsAllowedIconNameChar);
}

bool DecodeBase64(const std::string &text, std::vector<uint8_t> &data)
{
    data.clear();
    if (text.empty() || text.size() % BASE64_GROUP_SIZE != 0) {
        return false;
    }
    size_t firstPad = text.find('=');
    if (firstPad != std::string::npos && firstPad + BASE64_MAX_PADDING < text.size()) {
        return false;
    }
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    ENSURE_OR_RETURN_VAL(ctx != nullptr, false);
    ScopeGuard ctxGuard([ctx]() { EVP_ENCODE_CTX_free(ctx); });

    EVP_DecodeInit(ctx);
    std::vector<uint8_t> decoded(text.size() / BASE64_GROUP_SIZE * BASE64_GROUP_BYTES);
    int len = 0;
    int ret = EVP_DecodeUpdate(ctx, decoded.data(), &len, reinterpret_cast<const unsigned char *>(text.data()),
        static_cast<int>(text.size()));
    ENSURE_OR_RETURN_VAL(ret >= 0, false);
    int total = len;
    ret = EVP_DecodeFinal(ctx, decoded.data() + total, &len);
    total += len;
    if (ret != 1 || total <= 0 || static_cast<size_t>(total) > decoded.size()) {
        return false;
    }
    decoded.resize(static_cast<size_t>(total));
    data = std::move(decoded);
    return true;
}
} // namespace

std::string BuildIconDirectory(int32_t userId)
{
    return std::string(g_iconStoreRoot) + ICON_PATH_SEPARATOR + std::to_string(userId) + ICON_PATH_SEPARATOR +
        ICON_STORE_LEAF;
}

void SetIconStoreRootForTest(const std::string &root)
{
    g_iconStoreRoot = root;
}

ResultCode ParseIconSelectionContext(const std::vector<uint8_t> &context, CompanionIcon &icon)
{
    icon.fileName.clear();
    icon.data.clear();
    if (context.size() > MAX_ARRAY_LENGTH) {
        IAM_LOGE("selectionContext too large: %{public}zu", context.size());
        return INVALID_PARAMETERS;
    }
    auto json = TryParseJson(context);
    if (!json.has_value() || !json->is_object()) {
        IAM_LOGE("selectionContext is not a JSON object");
        return INVALID_PARAMETERS;
    }
    std::string fileName;
    if (!GetJsonField(*json, ICON_FILE_NAME_KEY, fileName, MAX_ARRAY_LENGTH)) {
        IAM_LOGE("icon_file_name missing or not a string");
        return INVALID_PARAMETERS;
    }
    std::string base64Data;
    if (!GetJsonField(*json, ICON_DATA_KEY, base64Data, MAX_ARRAY_LENGTH)) {
        IAM_LOGE("icon_data missing or not a string");
        return INVALID_PARAMETERS;
    }
    if (!IsValidIconFileName(fileName)) {
        IAM_LOGE("icon_file_name is invalid");
        return INVALID_PARAMETERS;
    }
    if (!DecodeBase64(base64Data, icon.data)) {
        IAM_LOGE("icon_data is not valid base64");
        return INVALID_PARAMETERS;
    }
    icon.fileName = std::move(fileName);
    return SUCCESS;
}

ResultCode SaveIconToDirectory(const std::string &iconDir, const CompanionIcon &icon)
{
    if (!IsValidIconFileName(icon.fileName)) {
        IAM_LOGE("icon file name is invalid");
        return INVALID_PARAMETERS;
    }
    if (iconDir.empty()) {
        IAM_LOGE("icon directory is empty");
        return INVALID_PARAMETERS;
    }
    if (!ForceCreateDirectory(iconDir)) {
        IAM_LOGE("create icon directory failed: %{public}s", iconDir.c_str());
        return GENERAL_ERROR;
    }
    std::string tmpPath = iconDir + ICON_PATH_SEPARATOR + icon.fileName + ICON_TMP_SUFFIX;
    std::string targetPath = iconDir + ICON_PATH_SEPARATOR + icon.fileName;

    UniqueFd fd(open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR));
    if (fd < 0) {
        IAM_LOGE("open tmp icon file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    // Unlink the tmp file on any failure path; Cancel() keeps it after a successful rename.
    ScopeGuard tmpGuard([&tmpPath]() { unlink(tmpPath.c_str()); });
    size_t offset = 0;
    while (offset < icon.data.size()) {
        ssize_t written = write(fd, icon.data.data() + offset, icon.data.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            IAM_LOGE("write tmp icon file failed errno=%{public}d", errno);
            return GENERAL_ERROR;
        }
        offset += static_cast<size_t>(written);
    }
    // fdatasync is the real durability and error gate before rename; UniqueFd's destructor closes the fd on return.
    if (fdatasync(fd) != 0) {
        IAM_LOGE("sync tmp icon file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    if (rename(tmpPath.c_str(), targetPath.c_str()) != 0) {
        IAM_LOGE("rename tmp icon file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    tmpGuard.Cancel();
    IAM_LOGI("icon saved: %{public}s size=%{public}zu", targetPath.c_str(), icon.data.size());
    return SUCCESS;
}

ResultCode DeleteIconFromDirectory(const std::string &iconDir, const std::string &iconFileName)
{
    if (!IsValidIconFileName(iconFileName)) {
        IAM_LOGE("icon file name is invalid");
        return INVALID_PARAMETERS;
    }
    if (iconDir.empty()) {
        IAM_LOGE("icon directory is empty");
        return INVALID_PARAMETERS;
    }
    std::string targetPath = iconDir + ICON_PATH_SEPARATOR + iconFileName;
    if (unlink(targetPath.c_str()) != 0) {
        if (errno == ENOENT) {
            IAM_LOGI("icon already absent: %{public}s", targetPath.c_str());
            return SUCCESS;
        }
        IAM_LOGE("unlink icon file failed errno=%{public}d path=%{public}s", errno, targetPath.c_str());
        return GENERAL_ERROR;
    }
    IAM_LOGI("icon deleted: %{public}s", targetPath.c_str());
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
