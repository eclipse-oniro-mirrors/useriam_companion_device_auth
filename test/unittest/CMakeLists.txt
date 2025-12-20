cmake_minimum_required(VERSION 3.18)

project(companion_device_auth_unittest LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (defaults to Debug for unit tests)" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CDA_ENABLE_COVERAGE "Enable coverage instrumentation for unit tests" OFF)
option(CDA_INCLUDE_IDL "Include generated IDL sources when available" OFF)

set(CDA_TEST_DIR "${CMAKE_CURRENT_LIST_DIR}")
get_filename_component(CDA_MODULE_DIR "${CDA_TEST_DIR}/../.." ABSOLUTE)
get_filename_component(CDA_SERVICES_DIR "${CDA_MODULE_DIR}/services" ABSOLUTE)
get_filename_component(CDA_PARENT_DIR "${CDA_MODULE_DIR}/.." ABSOLUTE)
get_filename_component(CDA_ROOT_CANDIDATE "${CDA_PARENT_DIR}/.." ABSOLUTE)

set(OHOS_ROOT "" CACHE PATH "Path to the OpenHarmony source root (should contain base/, foundation/, third_party/, ...)")

set(_cda_root_candidates "")
if(CDA_ROOT_CANDIDATE)
    list(APPEND _cda_root_candidates "${CDA_ROOT_CANDIDATE}")
endif()

foreach(_env_var IN ITEMS OHOS_ROOT OHOS_SOURCE_ROOT OHOS_PATH OHOS_BUILDROOT)
    if(DEFINED ENV{${_env_var}} AND NOT "$ENV{${_env_var}}" STREQUAL "")
        list(APPEND _cda_root_candidates "$ENV{${_env_var}}")
    endif()
endforeach()

if(DEFINED ENV{HOME})
    list(APPEND _cda_root_candidates "$ENV{HOME}/code/OH/code")
endif()

list(REMOVE_DUPLICATES _cda_root_candidates)

if(NOT OHOS_ROOT)
    foreach(_candidate IN LISTS _cda_root_candidates)
        if(_candidate AND EXISTS "${_candidate}/base")
            set(OHOS_ROOT "${_candidate}" CACHE PATH "Detected OpenHarmony source root" FORCE)
            break()
        endif()
    endforeach()
endif()

if(NOT OHOS_ROOT)
    message(FATAL_ERROR "OHOS_ROOT is not set or could not be auto-detected. "
                        "Set the OHOS_ROOT environment variable or pass -DOHOS_ROOT=/path/to/OpenHarmony.")
endif()

if(CDA_ENABLE_COVERAGE)
    message(STATUS "CDA_ENABLE_COVERAGE=ON: enabling --coverage with minimal debug symbols for test instrumentation")
    add_compile_options(-O0 -g1 --coverage)
    add_link_options(--coverage)
else()
    # For non-coverage builds, use minimal debug symbols to reduce compile time and object file size
    # -g1 provides minimal debug info (line numbers, function names) without full type information
    message(STATUS "Using minimal debug symbols (-g1) to reduce compilation time and binary size")
    add_compile_options(-g1)
endif()

set(CDA_LOCAL_INCLUDE_DIRS
    "${CDA_SERVICES_DIR}/common/inc"
    "${CDA_SERVICES_DIR}/companion/inc"
    "${CDA_SERVICES_DIR}/cross_device_comm/inc"
    "${CDA_SERVICES_DIR}/cross_device_entry/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction"
    "${CDA_SERVICES_DIR}/cross_device_interaction/add_companion/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/auth_maintain_state_change/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/common/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/handler/inc"
    "${CDA_SERVICES_DIR}/request/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/issue_token/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/keep_alive/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/obtain_token/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/remove_host_binding/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/revoke_token/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/sync_device_status/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/token_auth/inc"
    "${CDA_SERVICES_DIR}/cross_device_interaction/mix_auth/inc"
    "${CDA_SERVICES_DIR}/cross_device_msg/inc"
    "${CDA_SERVICES_DIR}/fwk_comm/inc"
    "${CDA_SERVICES_DIR}/host_binding/inc"
    "${CDA_SERVICES_DIR}/misc/inc"
    "${CDA_SERVICES_DIR}/security_agent/cpp/inc"
    "${CDA_SERVICES_DIR}/security_agent/gen"
    "${CDA_SERVICES_DIR}/service_entry/inc"
    "${CDA_SERVICES_DIR}/service_entry/src"
    "${CDA_SERVICES_DIR}/singleton/inc"
    "${CDA_SERVICES_DIR}/singleton/inc/companion"
    "${CDA_SERVICES_DIR}/singleton/inc/cross_device_comm"
    "${CDA_SERVICES_DIR}/singleton/inc/cross_device_interaction"
    "${CDA_SERVICES_DIR}/singleton/inc/host_binding"
    "${CDA_SERVICES_DIR}/singleton/inc/misc"
    "${CDA_SERVICES_DIR}/singleton/inc/request"
    "${CDA_SERVICES_DIR}/singleton/inc/security_agent"
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/inc"
    "${CDA_SERVICES_DIR}/utils/inc"
    "${CDA_MODULE_DIR}/common/inc"
    "${CDA_MODULE_DIR}/frameworks/native/ipc/idl"
)

set(_cda_kernel_uapi_include "")
if(OHOS_ROOT)
    set(_cda_kernel_patch_root "${OHOS_ROOT}/kernel/linux/patches")
    if(EXISTS "${_cda_kernel_patch_root}")
        file(GLOB _cda_kernel_variants LIST_DIRECTORIES TRUE "${_cda_kernel_patch_root}/linux-*")
        if(_cda_kernel_variants)
            list(SORT _cda_kernel_variants COMPARE NATURAL ORDER DESCENDING)
            foreach(_kernel_dir IN LISTS _cda_kernel_variants)
                set(_candidate "${_kernel_dir}/prebuilts/usr/include")
                if(EXISTS "${_candidate}/linux/ashmem.h")
                    set(_cda_kernel_uapi_include "${_candidate}")
                    break()
                endif()
            endforeach()
        endif()
    endif()
endif()

set(_cda_idl_gen_dir "")
if(OHOS_ROOT)
    set(_idl_candidates
        "${OHOS_ROOT}/out/rk3568/gen/base/useriam/companion_device_auth/frameworks/native/ipc"
        "${OHOS_ROOT}/out/gen/base/useriam/companion_device_auth/frameworks/native/ipc"
        "${CDA_MODULE_DIR}/frameworks/native/idl"
    )
    foreach(_candidate IN LISTS _idl_candidates)
        if(EXISTS "${_candidate}")
            set(_cda_idl_gen_dir "${_candidate}")
            break()
        endif()
    endforeach()

    if(NOT _cda_idl_gen_dir)
        set(_cda_idl_gen_dir "${CDA_MODULE_DIR}/frameworks/native/idl")
        message(WARNING "IDL generated files not found. Using IDL source directory as fallback: ${_cda_idl_gen_dir}")
    endif()
endif()

set(CDA_EXTERNAL_INCLUDE_DIRS
    "${OHOS_ROOT}/base/hiviewdfx/hilog/interfaces/native/innerkits/include"
    "${OHOS_ROOT}/third_party/bounds_checking_function/include"
    "${OHOS_ROOT}/third_party/bounds_checking_function/src"
    "${OHOS_ROOT}/base/useriam/companion_device_auth/interface/inner_api"
    "${OHOS_ROOT}/base/security/access_token/interfaces/innerkits/accesstoken/include"
    "${OHOS_ROOT}/base/security/access_token/interfaces/innerkits/token_setproc/include"
    "${OHOS_ROOT}/commonlibrary/c_utils/base/include"
    "${OHOS_ROOT}/foundation/communication/ipc/dl_deps"
    "${OHOS_ROOT}/foundation/communication/ipc/interfaces/innerkits/ipc_core/include"
    "${OHOS_ROOT}/foundation/communication/ipc/ipc/native/src/core/dbinder/include"
    "${OHOS_ROOT}/foundation/communication/ipc/ipc/native/src/core/framework/include"
    "${OHOS_ROOT}/foundation/communication/ipc/ipc/native/src/core/invoker/include"
    "${OHOS_ROOT}/foundation/systemabilitymgr/safwk/interfaces/innerkits/safwk"
    "${OHOS_ROOT}/foundation/systemabilitymgr/safwk/services/safwk/include"
    "${OHOS_ROOT}/foundation/systemabilitymgr/samgr/services/lsamgr/include"
    "${OHOS_ROOT}/foundation/systemabilitymgr/samgr/interfaces/innerkits/samgr_proxy/include"
    "${OHOS_ROOT}/base/useriam/user_auth_framework/interfaces/inner_api"
    "${OHOS_ROOT}/base/useriam/user_auth_framework/interfaces/inner_api/iam_executor"
    "${OHOS_ROOT}/interfaces/native/innerkits/include/"
    "${OHOS_ROOT}/base/hiviewdfx/hicollie/interfaces/native/innerkits/include"
    "${OHOS_ROOT}/base/useriam/companion_device_auth/frameworks/native/src/ipc_common"
    "${OHOS_ROOT}/foundation/communication/dsoftbus/interfaces/kits/transport"
    "${OHOS_ROOT}/foundation/communication/dsoftbus/interfaces/kits/common"
    "${OHOS_ROOT}/foundation/distributedhardware/device_manager/interfaces/inner_kits/native_cpp/include"
    "${_cda_idl_gen_dir}"
    "${OHOS_ROOT}/base/account/os_account/interfaces/innerkits/osaccount/native/include/"
    "${OHOS_ROOT}/base/account/os_account/interfaces/innerkits/domain_account/native/include/"
    "${OHOS_ROOT}/base/account/os_account/interfaces/innerkits/common/include"
    "${OHOS_ROOT}/base/startup/init/interfaces/innerkits/include"
    "${OHOS_ROOT}/base/startup/init/interfaces/innerkits/include/syspara/"
    "${OHOS_ROOT}/foundation/ability/ability_base/interfaces/kits/native/want/include"
    "${OHOS_ROOT}/foundation/ability/ability_base/interfaces/kits/native/uri/include/"
    "${OHOS_ROOT}/foundation/ability/ability_base/interfaces/inner_api/base/include/"
    "${OHOS_ROOT}/third_party/json/include/"
    "${OHOS_ROOT}/foundation/communication/dsoftbus/interfaces/kits/bus_center/"
    "${OHOS_ROOT}/foundation/communication/dsoftbus/interfaces/kits/common/"
    "${OHOS_ROOT}/foundation/communication/dsoftbus/interfaces/kits/transport"
    "${OHOS_ROOT}/foundation/communication/ipc/utils/include"
    "${OHOS_ROOT}/base/hiviewdfx/hitrace/interfaces/native/innerkits/include"
)

if(_cda_kernel_uapi_include)
    list(APPEND CDA_EXTERNAL_INCLUDE_DIRS "${_cda_kernel_uapi_include}")
endif()

set(CDA_INCLUDE_DIRS
    "${CDA_TEST_DIR}/services/cpp/fake"
    "${CDA_TEST_DIR}/services/cpp/mock"
    "${CDA_TEST_DIR}/services/cpp/fake/self"
    "${CDA_TEST_DIR}/services/cpp/fake/device_manager"
    "${CDA_TEST_DIR}/services/cpp/fake/softbus"
    "${CDA_TEST_DIR}/services/cpp/fake/system"
    "${CDA_TEST_DIR}/services/cpp/fake/user_auth_framework"
    "${CDA_TEST_DIR}/services/cpp/fake/access_token"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del"
)

foreach(dir IN LISTS CDA_LOCAL_INCLUDE_DIRS CDA_EXTERNAL_INCLUDE_DIRS)
    if(dir AND EXISTS "${dir}")
        list(APPEND CDA_INCLUDE_DIRS "${dir}")
    endif()
endforeach()
# Fallback for nlohmann/json when OHOS_ROOT is not set but the local tree exists.

list(REMOVE_DUPLICATES CDA_INCLUDE_DIRS)

set(CDA_SERVICE_SOURCES
    # Utils
    "${CDA_SERVICES_DIR}/utils/src/cda_attributes.cpp"
    "${CDA_SERVICES_DIR}/utils/src/callback_death_recipient.cpp"
    # relative_timer.cpp excluded - using fake implementation instead
    # "${CDA_SERVICES_DIR}/utils/src/resident_task_runner.cpp"
    "${CDA_SERVICES_DIR}/utils/src/subscription.cpp"
    # task_runner_manager.cpp excluded - using fake implementation instead
    # "${CDA_SERVICES_DIR}/utils/src/temporary_task_runner.cpp"
    # "${CDA_SERVICES_DIR}/utils/src/xcollie_helper.cpp"
    "${CDA_SERVICES_DIR}/utils/src/sa_status_listener.cpp"

    # Security Agent FFI
    "${CDA_SERVICES_DIR}/security_agent/cpp/src/companion_device_auth_ffi_util.cpp"

    # Misc (common)
    "${CDA_SERVICES_DIR}/cross_device_interaction/handler/src/incoming_message_handler_registry.cpp"
    "${CDA_SERVICES_DIR}/misc/src/misc_manager_impl.cpp"
    "${CDA_SERVICES_DIR}/misc/src/system_param_manager_impl.cpp"
    # Only include one active user ID manager implementation to avoid symbol collision
    # "${CDA_SERVICES_DIR}/misc/src/default_active_user_id_manager.cpp"  # Has external dependencies on OsAccountManager
    "${CDA_SERVICES_DIR}/misc/src/constant_active_user_id_manager.cpp"

    # Cross-device communication core modules
    "${CDA_SERVICES_DIR}/cross_device_comm/src/channel_manager.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/connection_manager.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/cross_device_comm_manager_impl.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/device_status_entry.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/device_status_manager.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/local_device_status_manager.cpp"
    "${CDA_SERVICES_DIR}/cross_device_comm/src/message_router.cpp"

    # SoftBus channel implementation
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/src/soft_bus_connection_manager.cpp"
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/src/soft_bus_channel.cpp"
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/src/soft_bus_device_status_manager.cpp"
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/src/soft_bus_global_callbacks.cpp"
    "${CDA_SERVICES_DIR}/soft_bus_cross_device_channel/src/soft_bus_socket.cpp"

    # Framework communication
    "${CDA_SERVICES_DIR}/fwk_comm/src/companion_auth_interface_adapter.cpp"
    "${CDA_SERVICES_DIR}/fwk_comm/src/companion_device_auth_all_in_one_executor.cpp"
    "${CDA_SERVICES_DIR}/fwk_comm/src/companion_device_auth_driver.cpp"
    "${CDA_SERVICES_DIR}/fwk_comm/src/companion_device_auth_executor_callback.cpp"
    "${CDA_SERVICES_DIR}/fwk_comm/src/fwk_comm_manager.cpp"

    # Singleton manager
    "${CDA_SERVICES_DIR}/singleton/src/singleton_manager.cpp"

    # Host binding
    "${CDA_SERVICES_DIR}/host_binding/src/host_binding.cpp"
    "${CDA_SERVICES_DIR}/host_binding/src/host_binding_manager_impl.cpp"

    # Request base modules
    "${CDA_SERVICES_DIR}/cross_device_interaction/common/src/inbound_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/handler/src/async_incoming_message_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/handler/src/sync_incoming_message_handler.cpp"
    "${CDA_SERVICES_DIR}/request/src/base_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/common/src/outbound_request.cpp"
    "${CDA_SERVICES_DIR}/request/src/request_factory_impl.cpp"
    "${CDA_SERVICES_DIR}/request/src/request_manager_impl.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/common/src/common_message.cpp"

    # # Request add companion
    "${CDA_SERVICES_DIR}/cross_device_interaction/add_companion/src/add_companion_message.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/add_companion/src/companion_add_companion_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/add_companion/src/companion_init_key_negotiation_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/add_companion/src/host_add_companion_request.cpp"

    # # Request companion auth maintain state change
    "${CDA_SERVICES_DIR}/cross_device_interaction/auth_maintain_state_change/src/auth_maintain_state_change_message.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/auth_maintain_state_change/src/companion_auth_maintain_state_change_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/auth_maintain_state_change/src/host_auth_maintain_state_change_handler.cpp"

    # # # Request companion revoke token
    "${CDA_SERVICES_DIR}/cross_device_interaction/revoke_token/src/companion_revoke_token_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/revoke_token/src/host_revoke_token_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/revoke_token/src/revoke_token_message.cpp"

    # # # Request delegate auth
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/src/companion_delegate_auth_callback.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/src/companion_delegate_auth_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/src/companion_start_delegate_auth_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/src/delegate_auth_message.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/delegate_auth/src/host_delegate_auth_request.cpp"

    # # # Request issue token
    "${CDA_SERVICES_DIR}/cross_device_interaction/issue_token/src/companion_issue_token_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/issue_token/src/companion_pre_issue_token_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/issue_token/src/issue_token_message.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/issue_token/src/host_issue_token_request.cpp"

    # # # Request obtain token
    "${CDA_SERVICES_DIR}/cross_device_interaction/obtain_token/src/companion_obtain_token_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/obtain_token/src/host_obtain_token_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/obtain_token/src/host_pre_obtain_token_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/obtain_token/src/obtain_token_message.cpp"

    # # # Request remove host binding
    "${CDA_SERVICES_DIR}/cross_device_interaction/remove_host_binding/src/companion_remove_host_binding_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/remove_host_binding/src/host_remove_host_binding_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/remove_host_binding/src/remove_host_binding_message.cpp"

    # # Request sync device status
    "${CDA_SERVICES_DIR}/cross_device_interaction/sync_device_status/src/companion_sync_device_status_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/sync_device_status/src/host_sync_device_status_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/sync_device_status/src/sync_device_status_message.cpp"

    # # # Request token auth
    "${CDA_SERVICES_DIR}/cross_device_interaction/token_auth/src/companion_token_auth_handler.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/token_auth/src/host_token_auth_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/token_auth/src/token_auth_message.cpp"

    # Request mix auth
    "${CDA_SERVICES_DIR}/cross_device_interaction/mix_auth/src/host_mix_auth_request.cpp"
    "${CDA_SERVICES_DIR}/cross_device_interaction/mix_auth/src/host_single_mix_auth_request.cpp"

    # Request keep alive
    "${CDA_SERVICES_DIR}/cross_device_interaction/keep_alive/src/keep_alive_handler.cpp"

    # Companion manager
    "${CDA_SERVICES_DIR}/companion/src/companion.cpp"
    "${CDA_SERVICES_DIR}/companion/src/companion_manager_impl.cpp"

    # Service entry
    "${CDA_SERVICES_DIR}/service_entry/src/available_device_subscription.cpp"
    # "${CDA_SERVICES_DIR}/service_entry/src/companion_device_auth_service.cpp"
    "${CDA_SERVICES_DIR}/service_entry/src/continuous_auth_subscription.cpp"
    "${CDA_SERVICES_DIR}/service_entry/src/subscription_util.cpp"
    "${CDA_SERVICES_DIR}/service_entry/src/subscription_manager.cpp"
    "${CDA_SERVICES_DIR}/service_entry/src/template_status_subscription.cpp"
)

if(CDA_INCLUDE_IDL AND _cda_idl_gen_dir AND EXISTS "${_cda_idl_gen_dir}")
    file(GLOB _cda_idl_gen_sources "${_cda_idl_gen_dir}/*.cpp")
    list(APPEND CDA_SERVICE_SOURCES ${_cda_idl_gen_sources})
endif()

list(APPEND CDA_SERVICE_SOURCES
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/securec.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/device_manager/device_manager.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/softbus/softbus.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/system/parameter.cpp"
    # "${CDA_TEST_DIR}/services/cpp/fake/system/thread_pool.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/user_auth_framework/user_auth_client.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/user_auth_framework/idriver_manager.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/access_token/token_setproc.cpp"
    # "${CDA_TEST_DIR}/services/cpp/fake/self/timer_stub.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/self/task_runner_manager.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/self/relative_timer.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/log.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/ipc_stub.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/ipc_skeleton_stub.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/fake_ipc_set_device_select_result_callback_stub.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/fake_system_ability_manager_client.cpp"
    "${CDA_TEST_DIR}/services/cpp/fake/to_del/fake_system_ability_status_change_stub.cpp"
    "${OHOS_ROOT}/commonlibrary/c_utils/base/src/refbase.cpp"
    "${OHOS_ROOT}/commonlibrary/c_utils/base/src/parcel.cpp"
    "${OHOS_ROOT}/base/useriam/user_auth_framework/frameworks/native/executors/src/iauth_executor_hdi.cpp"
    "${OHOS_ROOT}/base/useriam/user_auth_framework/frameworks/native/common/attributes/src/attributes.cpp"
)

add_library(companion_device_auth_services OBJECT ${CDA_SERVICE_SOURCES})
target_include_directories(companion_device_auth_services PUBLIC ${CDA_INCLUDE_DIRS})
target_compile_definitions(companion_device_auth_services PUBLIC ENABLE_TEST)

set_property(TARGET companion_device_auth_services PROPERTY CXX_STANDARD 17)
set_property(TARGET companion_device_auth_services PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET companion_device_auth_services PROPERTY CXX_EXTENSIONS OFF)

target_compile_definitions(companion_device_auth_services PRIVATE
    V8_DEPRECATION_WARNINGS
    _GNU_SOURCE
    HAVE_SYS_UIO_H
    __MUSL__
    _LIBCPP_HAS_MUSL_LIBC
    __BUILD_LINUX_WITH_CLANG
    __STDC_CONSTANT_MACROS
    __STDC_FORMAT_MACROS
    COMPONENT_BUILD
    CHROMIUM_CXX_TWEAK_INLINES
    NDEBUG
    NVALGRIND
    DYNAMIC_ANNOTATIONS_ENABLED=0
    PANDA_JS_ETS_HYBRID_MODE
    OHOS_PLATFORM
    CONFIG_STANDARD_SYSTEM
    BUILD_PUBLIC_VERSION
)

set(CDA_COMPILE_OPTIONS
    -fno-strict-aliasing
    -fPIC
    -fvisibility=default
    -fvisibility-inlines-hidden
    -fdata-sections
    -ffunction-sections
    -fomit-frame-pointer
    # -fno-rtti
    -Wall
    -Wextra
    -Werror
    -Wno-error=format
    -Wno-format
    -Wno-unused-parameter
    -Wno-error=attributes
    -Wno-error=overloaded-virtual
    -Wno-enum-constexpr-conversion
)

# Suppress 'os_log' format attribute warnings from OpenHarmony hilog headers.
# These headers use Apple-specific format attributes that GCC/Clang on Linux don't recognize.
add_compile_options(-Wno-error=format -Wno-format)

target_compile_options(companion_device_auth_services PRIVATE ${CDA_COMPILE_OPTIONS})
target_compile_options(companion_device_auth_services PRIVATE -include climits)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(companion_device_auth_services PRIVATE -fcolor-diagnostics)
endif()

find_package(Threads REQUIRED)
include(CTest)
enable_testing()

find_package(GTest QUIET)

if(NOT GTest_FOUND AND OHOS_ROOT AND EXISTS "${OHOS_ROOT}/third_party/googletest/CMakeLists.txt")
    message(STATUS "GTest not found via package config; falling back to ${OHOS_ROOT}/third_party/googletest")
    add_subdirectory("${OHOS_ROOT}/third_party/googletest" "${CMAKE_BINARY_DIR}/third_party/googletest")
endif()

if(NOT TARGET GTest::gtest)
    if(TARGET gtest)
        add_library(GTest::gtest ALIAS gtest)
    endif()
endif()
if(NOT TARGET GTest::gtest_main)
    if(TARGET gtest_main)
        add_library(GTest::gtest_main ALIAS gtest_main)
    endif()
endif()

if(NOT TARGET GTest::gtest OR NOT TARGET GTest::gtest_main)
    message(FATAL_ERROR "GTest not found. Install GTest (libgtest-dev) or set OHOS_ROOT to a tree containing third_party/googletest.")
endif()

include(GoogleTest)

add_executable(companion_device_auth_services_unittest
    # Utils
    "${CDA_TEST_DIR}/services/cpp/src/attributes_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/error_guard_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/relative_timer_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/scope_guard_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/subscription_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/callback_death_recipient_test.cpp"
    # "${CDA_TEST_DIR}/services/cpp/src/resident_task_runner_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_device_auth_ffi_util_test.cpp"

    # Cross-device communication core modules
    "${CDA_TEST_DIR}/services/cpp/src/device_status_manager_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/channel_manager_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/local_device_status_manager_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/connection_manager_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/cross_device_comm_manager_impl_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/device_status_entry_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/message_router_test.cpp"

    # Request add companion
    "${CDA_TEST_DIR}/services/cpp/src/host_add_companion_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_add_companion_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_init_key_negotiation_handler_test.cpp"

    # Request sync device status
    "${CDA_TEST_DIR}/services/cpp/src/host_sync_device_status_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_sync_device_status_handler_test.cpp"

    # Request remove host binding
    "${CDA_TEST_DIR}/services/cpp/src/companion_remove_host_binding_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_remove_host_binding_request_test.cpp"

    # Request companion revoke token
    "${CDA_TEST_DIR}/services/cpp/src/companion_revoke_token_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_revoke_token_handler_test.cpp"

    # Request obtain token
    "${CDA_TEST_DIR}/services/cpp/src/host_pre_obtain_token_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_obtain_token_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_obtain_token_request_test.cpp"

    # Request issue token
    "${CDA_TEST_DIR}/services/cpp/src/companion_pre_issue_token_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_issue_token_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_issue_token_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/issue_token_message_test.cpp"

    # Request companion auth maintain state change
    "${CDA_TEST_DIR}/services/cpp/src/host_auth_maintain_state_change_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_auth_maintain_state_change_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/auth_maintain_state_change_message_test.cpp"

    # Request delegate auth
    "${CDA_TEST_DIR}/services/cpp/src/companion_start_delegate_auth_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_delegate_auth_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_delegate_auth_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/delegate_auth_message_test.cpp"

    # Request keep alive
    "${CDA_TEST_DIR}/services/cpp/src/keep_alive_handler_test.cpp"

    # Request token auth
    "${CDA_TEST_DIR}/services/cpp/src/companion_token_auth_handler_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_token_auth_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/token_auth_message_test.cpp"

    # Request mix auth
    "${CDA_TEST_DIR}/services/cpp/src/host_mix_auth_request_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_single_mix_auth_request_test.cpp"

    # Request manager
    "${CDA_TEST_DIR}/services/cpp/src/request_manager_impl_test.cpp"

    # Companion manager
    "${CDA_TEST_DIR}/services/cpp/src/companion_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_manager_impl_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/companion_device_auth_service_test.cpp"

    # Host binding
    "${CDA_TEST_DIR}/services/cpp/src/host_binding_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/host_binding_manager_impl_test.cpp"

    # Service entry
    "${CDA_TEST_DIR}/services/cpp/src/available_device_subscription_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/continuous_auth_subscription_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/template_status_subscription_test.cpp"
    "${CDA_TEST_DIR}/services/cpp/src/subscription_manager_test.cpp"
)

target_link_libraries(companion_device_auth_services_unittest
    PRIVATE
        companion_device_auth_services
        GTest::gmock
        GTest::gtest
        GTest::gtest_main
        Threads::Threads
        dl
)
target_compile_features(companion_device_auth_services_unittest PRIVATE cxx_std_17)

gtest_discover_tests(companion_device_auth_services_unittest)
