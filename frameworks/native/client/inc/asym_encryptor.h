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

#ifndef ASYM_ENCRYPTOR_H
#define ASYM_ENCRYPTOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class AsymEncryptor {
public:
    virtual ~AsymEncryptor() = default;
    virtual std::optional<std::vector<uint8_t>> Encrypt(const std::vector<uint8_t> &plaintext) = 0;
};

std::unique_ptr<AsymEncryptor> CreateAsymEncryptor(AsymEncryptAlgorithm algorithm, std::vector<uint8_t> publicKey);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ASYM_ENCRYPTOR_H
