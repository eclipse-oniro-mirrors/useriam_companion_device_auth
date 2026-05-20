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

#include <cstddef>
#include <cstdint>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "common_defines.h"
#include "fuzz_registry.h"
#include "rsa_oaep_encryptor.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr size_t SIZE_10 = 10;
constexpr size_t SIZE_512 = 512;
constexpr size_t MINIMUM_REMAINING_BYTES = 10;
constexpr int32_t RSA_2048_KEY_BITS = 2048;

// Operation 0: Create with empty key
static void FuzzEncryptOp0(FuzzedDataProvider &fuzzData)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::vector<uint8_t> {}, RSA_2048_KEY_BITS);
    (void)encryptor;
}

// Operation 1: Create with random bytes as key, try encrypt
static void FuzzEncryptOp1(FuzzedDataProvider &fuzzData)
{
    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(keyData), RSA_2048_KEY_BITS);
    if (encryptor == nullptr) {
        return;
    }

    size_t plaintextSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> plaintext(plaintextSize);
    for (size_t i = 0; i < plaintextSize; ++i) {
        plaintext[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    (void)encryptor->Encrypt(plaintext);
}

// Operation 2: Create with random key, check HasPublicKey
static void FuzzEncryptOp2(FuzzedDataProvider &fuzzData)
{
    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(keyData), RSA_2048_KEY_BITS);
    if (encryptor != nullptr && encryptor->HasPublicKey()) {
        encryptor->Encrypt({});
    }
}

// Operation 3: Create and encrypt multiple times with same key
static void FuzzEncryptOp3(FuzzedDataProvider &fuzzData)
{
    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(keyData), RSA_2048_KEY_BITS);
    if (encryptor == nullptr) {
        return;
    }

    uint8_t iterations = fuzzData.ConsumeIntegralInRange<uint8_t>(1, 5);
    for (uint8_t i = 0; i < iterations; ++i) {
        if (fuzzData.remaining_bytes() < 1) {
            break;
        }
        size_t ptSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_10);
        std::vector<uint8_t> pt(ptSize);
        for (size_t j = 0; j < ptSize; ++j) {
            if (fuzzData.remaining_bytes() < 1) {
                break;
            }
            pt[j] = fuzzData.ConsumeIntegral<uint8_t>();
        }
        encryptor->Encrypt(pt);
    }
}

void FuzzRsaOaepEncryptor(FuzzedDataProvider &fuzzData)
{
    using FuzzOp = void (*)(FuzzedDataProvider &);
    static const FuzzOp fuzzOps[] = {
        FuzzEncryptOp0,
        FuzzEncryptOp1,
        FuzzEncryptOp2,
        FuzzEncryptOp3,
    };
    constexpr size_t numOps = sizeof(fuzzOps) / sizeof(FuzzOp);

    for (size_t i = 0; i < numOps; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        fuzzOps[i](fuzzData);
    }

    constexpr uint32_t loopCount = 20;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        size_t opIndex = fuzzData.ConsumeIntegralInRange<size_t>(0, numOps - 1);
        fuzzOps[opIndex](fuzzData);
    }
}

FUZZ_REGISTER(FuzzRsaOaepEncryptor)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
