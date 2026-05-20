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
#include <mutex>
#include <optional>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "cda_scope_guard.h"
#include "common_defines.h"
#include "errors.h"

#include "asym_encryptor.h"
#include "iipc_passcode_submit_callback.h"
#include "ipc_passcode_prompt_callback_service.h"
#include "ipc_passcode_submit_callback_stub.h"
#include "passcode_submit_callback_impl.h"
#include "rsa_oaep_encryptor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
// RSA-2048 DER-encoded SubjectPublicKeyInfo (generated for testing only)
constexpr uint8_t TEST_RSA_2048_PUB_KEY_DER[] = { 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
    0x01, 0x01, 0x00, 0x97, 0x1a, 0xbb, 0xde, 0x32, 0x7d, 0xf4, 0x7b, 0xae, 0xe8, 0x55, 0x8b, 0x08, 0xd9, 0x3c, 0xc5,
    0x28, 0x86, 0x98, 0x74, 0x99, 0x8f, 0xc2, 0xb8, 0x22, 0x7f, 0x15, 0xc8, 0x13, 0x12, 0x13, 0x54, 0xcc, 0xa1, 0x11,
    0x1d, 0xa8, 0x09, 0x56, 0xff, 0xaf, 0x35, 0x3c, 0x4c, 0x28, 0x3e, 0xb7, 0xce, 0x54, 0xc3, 0x56, 0xff, 0x6b, 0xff,
    0x0e, 0x63, 0xcb, 0xfb, 0x9c, 0xe8, 0x97, 0xea, 0x2d, 0x02, 0x69, 0x7d, 0x8d, 0x0b, 0xbb, 0xd1, 0x99, 0x95, 0x97,
    0xee, 0xad, 0xd7, 0x76, 0x62, 0x15, 0x98, 0xde, 0x5b, 0x1e, 0xfc, 0xa1, 0x36, 0xc3, 0xc9, 0x7c, 0x6c, 0x94, 0x0a,
    0x4a, 0xac, 0xcf, 0x17, 0xc8, 0x54, 0x17, 0xd7, 0x3a, 0x4b, 0xa6, 0x88, 0x6e, 0x85, 0x13, 0xe5, 0xc1, 0xd3, 0x6b,
    0x7b, 0x65, 0x7a, 0x0d, 0x22, 0x6a, 0xce, 0xb3, 0x72, 0x9b, 0x0c, 0x44, 0xd0, 0x4a, 0xd5, 0xf4, 0xf6, 0x01, 0x26,
    0xbb, 0x5d, 0x2c, 0x5b, 0xa7, 0xd1, 0xaa, 0x0f, 0x78, 0x24, 0x5f, 0x04, 0x8b, 0x9f, 0x48, 0x69, 0x8e, 0x2b, 0x9f,
    0x51, 0x8d, 0xf3, 0xb2, 0xeb, 0x47, 0x22, 0x83, 0xd9, 0x96, 0x54, 0x4a, 0x94, 0xc9, 0x12, 0x39, 0x15, 0x41, 0x3e,
    0xaf, 0x72, 0x9f, 0x28, 0x8a, 0x20, 0x3e, 0x56, 0x35, 0x1b, 0x74, 0x9f, 0x10, 0xa7, 0x98, 0xd0, 0x28, 0x98, 0xd0,
    0x2e, 0x74, 0x4f, 0xc6, 0xc5, 0x75, 0xb0, 0xf0, 0x50, 0x69, 0xc7, 0x41, 0x95, 0xb2, 0xdb, 0x05, 0x8f, 0xda, 0xd3,
    0x50, 0x60, 0x29, 0x5d, 0xda, 0xb3, 0xd6, 0x67, 0x0f, 0x39, 0x75, 0x66, 0xb2, 0x7f, 0xa6, 0xcf, 0x8a, 0x73, 0xe9,
    0x3f, 0xcd, 0xb3, 0x3c, 0x58, 0x17, 0x29, 0xe6, 0x9d, 0x11, 0x5a, 0x30, 0xe5, 0xd9, 0x19, 0x5d, 0x0e, 0x53, 0x05,
    0x34, 0x32, 0x10, 0x28, 0xb9, 0x62, 0x6a, 0x0e, 0xfb, 0xab, 0x97, 0xe1, 0x02, 0x03, 0x01, 0x00, 0x01 };
constexpr size_t TEST_RSA_2048_PUB_KEY_DER_LEN = 294;
constexpr size_t RSA_2048_CIPHERTEXT_SIZE = 256;
constexpr int32_t RSA_2048_KEY_BITS = 2048;

std::vector<uint8_t> GetValidRsa2048PublicKey()
{
    return std::vector<uint8_t>(TEST_RSA_2048_PUB_KEY_DER, TEST_RSA_2048_PUB_KEY_DER + TEST_RSA_2048_PUB_KEY_DER_LEN);
}

std::unique_ptr<AsymEncryptor> CreateTestEncryptor(std::vector<uint8_t> publicKey)
{
    return RsaOaepEncryptor::Create(std::move(publicKey), RSA_2048_KEY_BITS);
}

constexpr size_t RSA_4096_CIPHERTEXT_SIZE = 512;

std::vector<uint8_t> GenerateRsa4096PublicKeyDer()
{
    EVP_PKEY_CTX *keygenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (keygenCtx == nullptr) {
        return {};
    }
    ScopeGuard ctxGuard([&keygenCtx]() { EVP_PKEY_CTX_free(keygenCtx); });
    if (EVP_PKEY_keygen_init(keygenCtx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(keygenCtx, RSA_4096_KEY_BITS) <= 0) {
        return {};
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(keygenCtx, &pkey) <= 0) {
        return {};
    }
    ScopeGuard pkeyGuard([&pkey]() { EVP_PKEY_free(pkey); });

    int derLen = i2d_PUBKEY(pkey, nullptr);
    if (derLen <= 0) {
        return {};
    }
    std::vector<uint8_t> pubKeyDer(derLen);
    uint8_t *ptr = pubKeyDer.data();
    if (i2d_PUBKEY(pkey, &ptr) <= 0) {
        return {};
    }
    return pubKeyDer;
}

// Mock IPC submit callback for testing — inherits generated stub
class MockIpcPasscodeSubmitCallback : public IpcPasscodeSubmitCallbackStub {
public:
    MockIpcPasscodeSubmitCallback() = default;
    ~MockIpcPasscodeSubmitCallback() override = default;

    ErrCode OnPasscodeSubmit(const std::vector<uint8_t> &passcode) override
    {
        std::lock_guard<std::mutex> guard(mutex_);
        lastPasscode_ = passcode;
        submitCount_++;
        return returnCode_;
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

    void SetReturnCode(ErrCode code)
    {
        returnCode_ = code;
    }

    std::vector<uint8_t> GetLastPasscode()
    {
        std::lock_guard<std::mutex> guard(mutex_);
        return lastPasscode_;
    }

    size_t GetSubmitCount()
    {
        std::lock_guard<std::mutex> guard(mutex_);
        return submitCount_;
    }

private:
    std::mutex mutex_;
    ErrCode returnCode_ { ERR_OK };
    std::vector<uint8_t> lastPasscode_;
    size_t submitCount_ = 0;
};
} // namespace

class PasscodeSubmitCallbackImplTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// ============================================================================
// Null callback
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, NullCallback_DoesNotCrash, TestSize.Level0)
{
    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(nullptr, CreateTestEncryptor(GetValidRsa2048PublicKey()));
    EXPECT_NO_THROW(impl->OnPasscodeSubmit({ 0x01, 0x02, 0x03 }));
}

// ============================================================================
// No public key — encrypt fails, should not call IPC callback
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, NoPublicKey_DoesNotCallIpcCallback, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(std::vector<uint8_t> {}));
    impl->OnPasscodeSubmit({ 0x01, 0x02, 0x03 });
    EXPECT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(0));
}

// ============================================================================
// Invalid public key — encrypt fails, should not call IPC callback
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, InvalidPublicKey_DoesNotCallIpcCallback, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    std::vector<uint8_t> garbage(64, 0xFF);
    auto impl = std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(std::move(garbage)));
    impl->OnPasscodeSubmit({ 0x01, 0x02, 0x03 });
    EXPECT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(0));
}

// ============================================================================
// Valid key — encrypts and sends ciphertext (not plaintext)
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, ValidKey_SendsEncryptedCiphertext, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(GetValidRsa2048PublicKey()));

    std::vector<uint8_t> plaintext = { 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    impl->OnPasscodeSubmit(plaintext);

    ASSERT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(1));
    auto received = mockCallback->GetLastPasscode();
    // Ciphertext should be RSA-sized, not plaintext-sized
    EXPECT_EQ(received.size(), RSA_2048_CIPHERTEXT_SIZE);
    // Ciphertext should differ from plaintext
    EXPECT_NE(received.size(), plaintext.size());
}

// ============================================================================
// Valid key — same plaintext produces different ciphertext each time
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, ValidKey_DifferentCiphertextEachTime, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(GetValidRsa2048PublicKey()));

    std::vector<uint8_t> plaintext = { 0xAA, 0xBB, 0xCC };
    impl->OnPasscodeSubmit(plaintext);
    auto first = mockCallback->GetLastPasscode();

    impl->OnPasscodeSubmit(plaintext);
    auto second = mockCallback->GetLastPasscode();

    ASSERT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(2));
    EXPECT_NE(first, second);
}

// ============================================================================
// Valid key — empty plaintext is encrypted
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, ValidKey_EmptyPlaintext_Encrypted, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(GetValidRsa2048PublicKey()));

    std::vector<uint8_t> empty;
    impl->OnPasscodeSubmit(empty);

    ASSERT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(1));
    auto received = mockCallback->GetLastPasscode();
    EXPECT_EQ(received.size(), RSA_2048_CIPHERTEXT_SIZE);
}

// ============================================================================
// IPC callback returns error — should not crash
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, IpcCallbackError_DoesNotCrash, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    mockCallback->SetReturnCode(ERR_INVALID_VALUE);
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(GetValidRsa2048PublicKey()));

    EXPECT_NO_THROW(impl->OnPasscodeSubmit({ 0x01, 0x02, 0x03 }));
    EXPECT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(1));
}

// ============================================================================
// Plaintext too large for RSA — encrypt fails, no IPC call
// ============================================================================

HWTEST_F(PasscodeSubmitCallbackImplTest, PlaintextTooLarge_DoesNotCallIpc, TestSize.Level0)
{
    sptr<MockIpcPasscodeSubmitCallback> mockCallback = new MockIpcPasscodeSubmitCallback();
    auto impl =
        std::make_shared<PasscodeSubmitCallbackImpl>(mockCallback, CreateTestEncryptor(GetValidRsa2048PublicKey()));

    // RSA-2048 OAEP max plaintext is 190 bytes; 256 bytes exceeds it
    std::vector<uint8_t> largePlaintext(256, 0x42);
    impl->OnPasscodeSubmit(largePlaintext);
    EXPECT_EQ(mockCallback->GetSubmitCount(), static_cast<size_t>(0));
}

// ============================================================================
// IpcPasscodePromptCallbackService tests
// ============================================================================

namespace {
class FakePasscodePromptCallback : public IPasscodePromptCallback {
public:
    void OnPasscodePrompt(const std::shared_ptr<PasscodeSubmitCallback> &submit,
        const ClientPasscodePromptParams &options) override
    {
        receivedOptions_ = options;
        receivedSubmit_ = submit;
        callCount_++;
    }

    ClientPasscodePromptParams receivedOptions_;
    std::shared_ptr<PasscodeSubmitCallback> receivedSubmit_;
    size_t callCount_ = 0;
};
} // namespace

class IpcPasscodePromptCallbackServiceTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

HWTEST_F(IpcPasscodePromptCallbackServiceTest, NullImpl_ReturnsError, TestSize.Level0)
{
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(nullptr);
    sptr<MockIpcPasscodeSubmitCallback> submitCallback = new MockIpcPasscodeSubmitCallback();
    IpcPasscodePromptOptions options;
    options.challenge = { 0x01, 0x02 };
    options.publicKey = std::vector<unsigned char>(TEST_RSA_2048_PUB_KEY_DER,
        TEST_RSA_2048_PUB_KEY_DER + TEST_RSA_2048_PUB_KEY_DER_LEN);

    int32_t ret = service->OnPasscodePrompt(submitCallback, options);
    EXPECT_NE(ret, 0);
}

HWTEST_F(IpcPasscodePromptCallbackServiceTest, NullSubmitCallback_ReturnsError, TestSize.Level0)
{
    auto fakeImpl = std::make_shared<FakePasscodePromptCallback>();
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(fakeImpl);

    IpcPasscodePromptOptions options;
    options.challenge = { 0x01, 0x02 };

    int32_t ret = service->OnPasscodePrompt(nullptr, options);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(fakeImpl->callCount_, static_cast<size_t>(0));
}

HWTEST_F(IpcPasscodePromptCallbackServiceTest, ValidInputs_CallsImplWithChallenge, TestSize.Level0)
{
    auto fakeImpl = std::make_shared<FakePasscodePromptCallback>();
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(fakeImpl);
    sptr<MockIpcPasscodeSubmitCallback> submitCallback = new MockIpcPasscodeSubmitCallback();

    IpcPasscodePromptOptions options;
    options.challenge = { 0xAA, 0xBB, 0xCC };
    options.publicKey = GenerateRsa4096PublicKeyDer();
    options.asymEncryptAlgorithm = static_cast<int32_t>(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256);

    int32_t ret = service->OnPasscodePrompt(submitCallback, options);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(fakeImpl->callCount_, static_cast<size_t>(1));
    // Challenge should be forwarded to client options
    EXPECT_EQ(fakeImpl->receivedOptions_.challenge, options.challenge);
    // Submit callback should be provided
    EXPECT_NE(fakeImpl->receivedSubmit_, nullptr);
}

HWTEST_F(IpcPasscodePromptCallbackServiceTest, PublicKeyInOptions_SubmitCallbackCanEncrypt, TestSize.Level0)
{
    auto pubKeyDer = GenerateRsa4096PublicKeyDer();
    ASSERT_FALSE(pubKeyDer.empty());

    auto fakeImpl = std::make_shared<FakePasscodePromptCallback>();
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(fakeImpl);
    sptr<MockIpcPasscodeSubmitCallback> submitCallback = new MockIpcPasscodeSubmitCallback();

    IpcPasscodePromptOptions options;
    options.challenge = { 0x01 };
    options.asymEncryptAlgorithm = static_cast<int32_t>(AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256);
    options.publicKey = std::vector<unsigned char>(pubKeyDer.begin(), pubKeyDer.end());

    int32_t ret = service->OnPasscodePrompt(submitCallback, options);
    EXPECT_EQ(ret, 0);
    ASSERT_NE(fakeImpl->receivedSubmit_, nullptr);

    // Submit passcode through the received callback — should encrypt with the public key
    std::vector<uint8_t> passcode = { 0x50, 0x41, 0x53, 0x53 };
    fakeImpl->receivedSubmit_->OnPasscodeSubmit(passcode);

    ASSERT_EQ(submitCallback->GetSubmitCount(), static_cast<size_t>(1));
    auto received = submitCallback->GetLastPasscode();
    EXPECT_EQ(received.size(), RSA_4096_CIPHERTEXT_SIZE);
    EXPECT_NE(received.size(), passcode.size());
}

HWTEST_F(IpcPasscodePromptCallbackServiceTest, UnknownAlgorithm_ReturnsError, TestSize.Level0)
{
    auto fakeImpl = std::make_shared<FakePasscodePromptCallback>();
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(fakeImpl);
    sptr<MockIpcPasscodeSubmitCallback> submitCallback = new MockIpcPasscodeSubmitCallback();

    IpcPasscodePromptOptions options;
    options.challenge = { 0x01, 0x02 };
    options.asymEncryptAlgorithm = 0; // UNKNOWN

    int32_t ret = service->OnPasscodePrompt(submitCallback, options);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(fakeImpl->callCount_, static_cast<size_t>(0));
}

HWTEST_F(IpcPasscodePromptCallbackServiceTest, OutOfRangeAlgorithm_ReturnsError, TestSize.Level0)
{
    auto fakeImpl = std::make_shared<FakePasscodePromptCallback>();
    auto service = std::make_shared<IpcPasscodePromptCallbackService>(fakeImpl);
    sptr<MockIpcPasscodeSubmitCallback> submitCallback = new MockIpcPasscodeSubmitCallback();

    IpcPasscodePromptOptions options;
    options.challenge = { 0x01, 0x02 };
    options.asymEncryptAlgorithm = -1; // out of range

    int32_t ret = service->OnPasscodePrompt(submitCallback, options);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(fakeImpl->callCount_, static_cast<size_t>(0));
}
