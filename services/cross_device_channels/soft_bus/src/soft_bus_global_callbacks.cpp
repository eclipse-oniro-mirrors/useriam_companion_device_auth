/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_global_callbacks.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "service_common.h"
#include "soft_bus_channel_common.h"
#include "soft_bus_connection_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

constexpr int INVALID_SOCKET_ID = -1;
constexpr int MAX_DATA_LEN = 4096;
constexpr size_t PKG_NAME_MAX_LEN = 65;           // align with SoftBus PKG_NAME_SIZE_MAX
constexpr size_t SOFTBUS_NETWORK_ID_MAX_LEN = 65; // align with SoftBus NETWORK_ID_BUF_LEN

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
std::weak_ptr<SoftBusConnectionManager> g_softBusConnectionManager;
SoftBusConnectionManager *g_softBusConnectionManagerPtr { nullptr };
std::mutex g_adapterMutex;
} // namespace

void SetGlobalSoftBusConnectionManager(std::weak_ptr<SoftBusConnectionManager> adapter)
{
    std::lock_guard<std::mutex> lock(g_adapterMutex);
    auto lockedAdapter = adapter.lock();
    ENSURE_OR_RETURN(lockedAdapter != nullptr);
    g_softBusConnectionManager = adapter;
    g_softBusConnectionManagerPtr = lockedAdapter.get();
}

void ClearGlobalSoftBusConnectionManager(SoftBusConnectionManager *adapter)
{
    if (adapter == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_adapterMutex);
    if (g_softBusConnectionManagerPtr == adapter) {
        g_softBusConnectionManagerPtr = nullptr;
        g_softBusConnectionManager = {};
    }
}

void SoftBusOnBind(int32_t socket, PeerSocketInfo info)
{
    ENSURE_OR_RETURN(socket > INVALID_SOCKET_ID);
    ENSURE_OR_RETURN(info.networkId != nullptr);
    ENSURE_OR_RETURN(info.pkgName != nullptr);

    size_t pkgNameLen = strnlen(info.pkgName, PKG_NAME_MAX_LEN);
    std::string peerPkgName(info.pkgName, pkgNameLen);
    ENSURE_OR_RETURN(peerPkgName == PKG_NAME);

    size_t networkIdLen = strnlen(info.networkId, SOFTBUS_NETWORK_ID_MAX_LEN);
    ENSURE_OR_RETURN(networkIdLen < SOFTBUS_NETWORK_ID_MAX_LEN);
    std::string peerNetworkId(info.networkId, networkIdLen);

    std::lock_guard<std::mutex> lock(g_adapterMutex);
    IAM_LOGI("=> [SoftBus] SoftBusOnBind callback received, socket=%{public}d, networkId=%{public}s", socket,
        GET_MASKED_STR_CSTR(peerNetworkId));

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [weakAdapter = g_softBusConnectionManager, socket, peerNetworkId = std::move(peerNetworkId)]() {
            auto adapter = weakAdapter.lock();
            if (adapter != nullptr) {
                adapter->HandleBind(socket, peerNetworkId);
            }
        });
}

void SoftBusOnShutdown(int32_t socket, ShutdownReason reason)
{
    ENSURE_OR_RETURN(socket > INVALID_SOCKET_ID);

    std::lock_guard<std::mutex> lock(g_adapterMutex);
    IAM_LOGI("=> [SoftBus] SoftBusOnShutdown callback received, socket=%{public}d, reason=%{public}d", socket,
        static_cast<int32_t>(reason));

    TaskRunnerManager::GetInstance().PostTaskOnResident([weakAdapter = g_softBusConnectionManager, socket, reason]() {
        auto adapter = weakAdapter.lock();
        if (adapter != nullptr) {
            adapter->HandleShutdown(socket, static_cast<int32_t>(reason));
        }
    });
}

void SoftBusOnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    ENSURE_OR_RETURN(socket > INVALID_SOCKET_ID);
    ENSURE_OR_RETURN(data != nullptr);
    ENSURE_OR_RETURN(dataLen <= MAX_DATA_LEN);

    std::vector<uint8_t> dataCopy(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + dataLen);

    std::lock_guard<std::mutex> lock(g_adapterMutex);
    IAM_LOGI("=> [SoftBus] SoftBusOnBytes callback received, socket=%{public}d, dataLen=%{public}u", socket, dataLen);

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [weakAdapter = g_softBusConnectionManager, socket, dataCopy = std::move(dataCopy)]() {
            auto adapter = weakAdapter.lock();
            if (adapter != nullptr) {
                adapter->HandleBytes(socket, dataCopy.data(), dataCopy.size());
            }
        });
}

void SoftBusOnError(int32_t socket, int32_t errCode)
{
    ENSURE_OR_RETURN(socket > INVALID_SOCKET_ID);

    std::lock_guard<std::mutex> lock(g_adapterMutex);
    IAM_LOGE("=> [SoftBus] SoftBusOnError callback received, socket=%{public}d, errCode=%{public}d", socket, errCode);

    TaskRunnerManager::GetInstance().PostTaskOnResident([weakAdapter = g_softBusConnectionManager, socket, errCode]() {
        auto adapter = weakAdapter.lock();
        if (adapter != nullptr) {
            adapter->HandleError(socket, errCode);
        }
    });
}

bool SoftBusOnNegotiate(int32_t socket, PeerSocketInfo info)
{
    ENSURE_OR_RETURN_VAL(socket > INVALID_SOCKET_ID, false);

    ENSURE_OR_RETURN_VAL(info.pkgName != nullptr, false);
    size_t pkgNameLen = strnlen(info.pkgName, PKG_NAME_MAX_LEN);
    ENSURE_OR_RETURN_VAL(pkgNameLen < PKG_NAME_MAX_LEN, false);
    std::string peerPkgName(info.pkgName, pkgNameLen);
    ENSURE_OR_RETURN_VAL(peerPkgName == PKG_NAME, false);

    IAM_LOGI("=> [SoftBus] SoftBusOnNegotiate callback received, socket=%{public}d", socket);

    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
