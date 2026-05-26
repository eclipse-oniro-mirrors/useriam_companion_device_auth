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

#include "fuzz_registry.h"

#include "errors.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

#include "asym_encryptor.h"
#include "iipc_passcode_submit_callback.h"
#include "ipc_passcode_submit_callback_stub.h"
#include "passcode_submit_callback_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr size_t SIZE_10 = 10;
constexpr size_t SIZE_512 = 512;
constexpr size_t MINIMUM_REMAINING_BYTES = 10;

// Fuzz mock IPC submit callback
class FuzzMockPasscodeSubmitCallback : public IpcPasscodeSubmitCallbackStub {
public:
    FuzzMockPasscodeSubmitCallback() = default;
    ~FuzzMockPasscodeSubmitCallback() override = default;

    ErrCode OnPasscodeSubmit(const std::vector<uint8_t> &passcode) override
    {
        (void)passcode;
        return ERR_OK;
    }

    int32_t CallbackEnter(uint32_t code) override
    {
        (void)code;
        return ERR_OK;
    }

    int32_t CallbackExit(uint32_t code, int32_t result) override
    {
        (void)code;
        (void)result;
        return ERR_OK;
    }
};

// Operation 0: Null callback, valid key, random passcode
static void FuzzSubmitOp0(FuzzedDataProvider &fuzzData)
{
    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(nullptr,
        CreateAsymEncryptor(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256, std::move(keyData)));

    size_t passcodeSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> passcode(passcodeSize);
    for (size_t i = 0; i < passcodeSize; ++i) {
        passcode[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    impl->OnPasscodeSubmit(passcode);
}

// Operation 1: Valid mock callback, empty key, random passcode
static void FuzzSubmitOp1(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockPasscodeSubmitCallback> mockCallback = new FuzzMockPasscodeSubmitCallback();
    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback,
        CreateAsymEncryptor(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256, std::vector<uint8_t> {}));

    size_t passcodeSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> passcode(passcodeSize);
    for (size_t i = 0; i < passcodeSize; ++i) {
        passcode[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    impl->OnPasscodeSubmit(passcode);
}

// Operation 2: Valid mock callback, random key data, random passcode
static void FuzzSubmitOp2(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockPasscodeSubmitCallback> mockCallback = new FuzzMockPasscodeSubmitCallback();

    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback,
        CreateAsymEncryptor(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256, std::move(keyData)));

    size_t passcodeSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> passcode(passcodeSize);
    for (size_t i = 0; i < passcodeSize; ++i) {
        passcode[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }
    impl->OnPasscodeSubmit(passcode);
}

// Operation 3: Valid mock callback, random key, submit multiple times
static void FuzzSubmitOp3(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockPasscodeSubmitCallback> mockCallback = new FuzzMockPasscodeSubmitCallback();

    size_t keySize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_512);
    std::vector<uint8_t> keyData(keySize);
    for (size_t i = 0; i < keySize; ++i) {
        keyData[i] = fuzzData.ConsumeIntegral<uint8_t>();
    }

    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback,
        CreateAsymEncryptor(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256, std::move(keyData)));

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
        impl->OnPasscodeSubmit(pt);
    }
}

void FuzzPasscodeSubmitCallbackImpl(FuzzedDataProvider &fuzzData)
{
    using FuzzOp = void (*)(FuzzedDataProvider &);
    static const FuzzOp fuzzOps[] = {
        FuzzSubmitOp0,
        FuzzSubmitOp1,
        FuzzSubmitOp2,
        FuzzSubmitOp3,
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

FUZZ_REGISTER(FuzzPasscodeSubmitCallbackImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
