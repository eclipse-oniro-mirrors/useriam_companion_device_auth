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

#include "file_storage_adapter_impl.h"

#include <cerrno>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cda_scope_guard.h"
#include "directory_ex.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "unique_fd.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_FILE_STORAGE_ADAPTER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr const char *FILE_TMP_SUFFIX = ".tmp";
bool IsValidFileName(const std::string &fileName)
{
    return !fileName.empty() && fileName != "." && fileName != ".." && fileName.find('/') == std::string::npos;
}
} // namespace

std::shared_ptr<FileStorageAdapterImpl> FileStorageAdapterImpl::Create()
{
    auto adapter = std::make_shared<FileStorageAdapterImpl>(PrivateConstructTag {});
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    return adapter;
}

ResultCode FileStorageAdapterImpl::SaveFile(const std::string &dir, const std::string &fileName,
    const std::vector<uint8_t> &data)
{
    if (dir.empty() || !IsValidFileName(fileName)) {
        IAM_LOGE("invalid directory or file name");
        return INVALID_PARAMETERS;
    }
    if (!ForceCreateDirectory(dir)) {
        IAM_LOGE("create directory failed: %{public}s", dir.c_str());
        return GENERAL_ERROR;
    }
    std::string tmpPath = dir + '/' + fileName + FILE_TMP_SUFFIX;
    std::string targetPath = dir + '/' + fileName;

    UniqueFd fd(open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR));
    if (fd < 0) {
        IAM_LOGE("open tmp file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    // Unlink the tmp file on any failure path; Cancel() keeps it after a successful rename.
    ScopeGuard tmpGuard([&tmpPath]() { unlink(tmpPath.c_str()); });
    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t written = write(fd, data.data() + offset, data.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            IAM_LOGE("write tmp file failed errno=%{public}d", errno);
            return GENERAL_ERROR;
        }
        offset += static_cast<size_t>(written);
    }
    // fdatasync is the real durability and error gate before rename; UniqueFd's destructor closes
    // the fd on return.
    if (fdatasync(fd) != 0) {
        IAM_LOGE("sync tmp file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    if (rename(tmpPath.c_str(), targetPath.c_str()) != 0) {
        IAM_LOGE("rename tmp file failed errno=%{public}d", errno);
        return GENERAL_ERROR;
    }
    tmpGuard.Cancel();
    IAM_LOGI("file saved: %{public}s size=%{public}zu", targetPath.c_str(), data.size());
    return SUCCESS;
}

ResultCode FileStorageAdapterImpl::DeleteFile(const std::string &dir, const std::string &fileName)
{
    if (dir.empty() || !IsValidFileName(fileName)) {
        IAM_LOGE("invalid directory or file name");
        return INVALID_PARAMETERS;
    }
    std::string targetPath = dir + '/' + fileName;
    if (unlink(targetPath.c_str()) != 0) {
        if (errno == ENOENT) {
            IAM_LOGI("file already absent: %{public}s", targetPath.c_str());
            return SUCCESS;
        }
        IAM_LOGE("unlink file failed errno=%{public}d path=%{public}s", errno, targetPath.c_str());
        return GENERAL_ERROR;
    }
    IAM_LOGI("file deleted: %{public}s", targetPath.c_str());
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
