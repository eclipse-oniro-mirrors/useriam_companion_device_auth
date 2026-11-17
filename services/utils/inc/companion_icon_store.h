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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_ICON_STORE_H
#define COMPANION_DEVICE_AUTH_COMPANION_ICON_STORE_H

#include <cstdint>
#include <string>
#include <vector>

#include "common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
struct CompanionIcon {
    std::string fileName;
    std::vector<uint8_t> data;
};

constexpr const char *ICON_STORE_ROOT = "/data/service/el1";
constexpr const char *ICON_STORE_LEAF = "useriam/companion_device_auth/icons";
constexpr size_t MAX_ICON_FILE_NAME_LENGTH = 128;

// Icon files are stored per host user; the directory chain is created at runtime.
std::string BuildIconDirectory(int32_t userId);
void SetIconStoreRootForTest(const std::string &root);

// Base64 encoding layout: each group of 4 characters encodes 3 bytes, padded with up to 2 '='.
constexpr size_t BASE64_GROUP_SIZE = 4;
constexpr size_t BASE64_GROUP_BYTES = 3;
constexpr size_t BASE64_MAX_PADDING = 2;

ResultCode ParseIconSelectionContext(const std::vector<uint8_t> &context, CompanionIcon &icon);
ResultCode SaveIconToDirectory(const std::string &iconDir, const CompanionIcon &icon);
ResultCode DeleteIconFromDirectory(const std::string &iconDir, const std::string &iconFileName);
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_ICON_STORE_H
