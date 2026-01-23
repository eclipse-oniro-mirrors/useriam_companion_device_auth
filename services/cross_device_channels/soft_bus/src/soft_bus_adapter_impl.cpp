/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "soft_bus_adapter_impl.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "scope_guard.h"
#include "singleton_manager.h"
#include "socket.h"
#include "soft_bus_channel_common.h"
#include "softbus_error_code.h"
#include "xcollie_helper.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INVALID_SOCKET_ID = -1;
constexpr int32_t QOS_MIN_BW = 1024 * 1024;
constexpr int32_t QOS_MAX_LATENCY = 30 * 1000;
constexpr int32_t QOS_MIN_LATENCY = 100;
constexpr int32_t QOS_MAX_WAIT_TIMEOUT = 30 * 1000;
constexpr size_t SERVER_QOS = 4;
constexpr size_t CLIENT_QOS = 3;

std::shared_ptr<ISoftBusSocketCallback> g_callback;
std::mutex g_callbackMutex;

void SoftBusAdapterOnBind(int32_t socket, PeerSocketInfo info)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    ENSURE_OR_RETURN(g_callback != nullptr);
    std::string networkId(info.networkId ? info.networkId : "");
    g_callback->HandleBind(socket, networkId);
}

void SoftBusAdapterOnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    ENSURE_OR_RETURN(g_callback != nullptr);
    g_callback->HandleBytes(socket, data, dataLen);
}

void SoftBusAdapterOnShutdown(int32_t socket, ShutdownReason reason)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    ENSURE_OR_RETURN(g_callback != nullptr);
    g_callback->HandleShutdown(socket, static_cast<int32_t>(reason));
}

void SoftBusAdapterOnError(int32_t socket, int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    ENSURE_OR_RETURN(g_callback != nullptr);
    g_callback->HandleError(socket, errorCode);
}

bool SoftBusAdapterOnNegotiate(int32_t socket, PeerSocketInfo info)
{
    (void)socket;
    if (info.pkgName == nullptr) {
        return false;
    }
    std::string peerPkgName(info.pkgName);
    return peerPkgName == PKG_NAME;
}

} // namespace

void SoftBusAdapterImpl::RegisterCallback(std::shared_ptr<ISoftBusSocketCallback> callback)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    g_callback = callback;
    callback_ = callback;
}

std::optional<SocketId> SoftBusAdapterImpl::CreateServerSocket()
{
    SocketInfo info = {
        .name = const_cast<char *>(SERVER_SOCKET_NAME),
        .peerName = nullptr,
        .peerNetworkId = nullptr,
        .pkgName = const_cast<char *>(PKG_NAME),
        .dataType = DATA_TYPE_BYTES,
    };

    int32_t socketId = ::Socket(info);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("Create server socket failed: %{public}d", socketId);
        return std::nullopt;
    }

    ScopeGuard guard([socketId]() { ::Shutdown(socketId); });

    QosTV serverQos[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = QOS_MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = QOS_MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = QOS_MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = QOS_MAX_WAIT_TIMEOUT },
    };

    ISocketListener listener {};
    listener.OnBind = SoftBusAdapterOnBind;
    listener.OnBytes = SoftBusAdapterOnBytes;
    listener.OnShutdown = SoftBusAdapterOnShutdown;
    listener.OnError = SoftBusAdapterOnError;
    listener.OnNegotiate = SoftBusAdapterOnNegotiate;

    int32_t ret = ::Listen(socketId, serverQos, SERVER_QOS, &listener);
    if (ret != SOFTBUS_OK) {
        IAM_LOGE("Listen failed: %{public}d", ret);
        return std::nullopt;
    }

    guard.Cancel();

    IAM_LOGI("Server socket created and listening: %{public}d", socketId);
    return socketId;
}

std::optional<SocketId> SoftBusAdapterImpl::CreateClientSocket(const std::string &connectionName,
    const std::string &networkId)
{
    std::string socketName = std::string(CLIENT_SOCKET_NAME_PREFIX) + "." + connectionName;

    SocketInfo info = {
        .name = const_cast<char *>(socketName.c_str()),
        .peerName = const_cast<char *>(SERVER_SOCKET_NAME),
        .peerNetworkId = const_cast<char *>(networkId.c_str()),
        .pkgName = const_cast<char *>(PKG_NAME),
        .dataType = DATA_TYPE_BYTES,
    };

    int32_t socketId = ::Socket(info);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("Create client socket failed: %{public}d", socketId);
        return std::nullopt;
    }

    ScopeGuard guard([socketId]() { ::Shutdown(socketId); });

    QosTV clientQos[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = QOS_MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = QOS_MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = QOS_MIN_LATENCY },
    };

    ISocketListener listener {};
    listener.OnBind = SoftBusAdapterOnBind;
    listener.OnBytes = SoftBusAdapterOnBytes;
    listener.OnShutdown = SoftBusAdapterOnShutdown;
    listener.OnError = SoftBusAdapterOnError;
    listener.OnNegotiate = SoftBusAdapterOnNegotiate;

    int32_t ret = ::BindAsync(socketId, clientQos, CLIENT_QOS, &listener);
    if (ret != SOFTBUS_OK) {
        IAM_LOGE("BindAsync failed: %{public}d", ret);
        return std::nullopt;
    }

    guard.Cancel();

    IAM_LOGI("Client socket created: %{public}d", socketId);
    return socketId;
}

bool SoftBusAdapterImpl::SendBytes(int32_t socketId, const std::vector<uint8_t> &data)
{
    int32_t ret = ::SendBytes(socketId, data.data(), data.size());
    if (ret != SOFTBUS_OK) {
        IAM_LOGE("SendBytes failed: %{public}d", ret);
        return false;
    }
    return true;
}

void SoftBusAdapterImpl::ShutdownSocket(int32_t socketId)
{
    ::Shutdown(socketId);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
