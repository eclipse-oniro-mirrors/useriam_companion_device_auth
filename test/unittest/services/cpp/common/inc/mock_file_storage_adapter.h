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

#ifndef COMPANION_DEVICE_AUTH_MOCK_FILE_STORAGE_ADAPTER_H
#define COMPANION_DEVICE_AUTH_MOCK_FILE_STORAGE_ADAPTER_H

#include <cstdint>
#include <string>
#include <vector>

#include "file_storage_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Records every call and answers with a configurable result; nothing touches the file system.
class MockFileStorageAdapter : public IFileStorageAdapter {
public:
    struct SavedFile {
        std::string dir;
        std::string fileName;
        std::vector<uint8_t> data;

        bool operator==(const SavedFile &other) const
        {
            return dir == other.dir && fileName == other.fileName && data == other.data;
        }
    };

    struct DeletedFile {
        std::string dir;
        std::string fileName;

        bool operator==(const DeletedFile &other) const
        {
            return dir == other.dir && fileName == other.fileName;
        }
    };

    ResultCode SaveFile(const std::string &dir, const std::string &fileName, const std::vector<uint8_t> &data) override
    {
        savedFiles_.push_back(SavedFile { dir, fileName, data });
        return saveResult_;
    }

    ResultCode DeleteFile(const std::string &dir, const std::string &fileName) override
    {
        deletedFiles_.push_back(DeletedFile { dir, fileName });
        return deleteResult_;
    }

    void SetSaveResult(ResultCode result)
    {
        saveResult_ = result;
    }

    void SetDeleteResult(ResultCode result)
    {
        deleteResult_ = result;
    }

    const std::vector<SavedFile> &GetSavedFiles() const
    {
        return savedFiles_;
    }

    const std::vector<DeletedFile> &GetDeletedFiles() const
    {
        return deletedFiles_;
    }

private:
    ResultCode saveResult_ = ResultCode::SUCCESS;
    ResultCode deleteResult_ = ResultCode::SUCCESS;
    std::vector<SavedFile> savedFiles_;
    std::vector<DeletedFile> deletedFiles_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_FILE_STORAGE_ADAPTER_H
