cmake_minimum_required(VERSION 3.20)
project(AntiCheatDriver LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Windows Driver Kit configuration
set(WDK_VERSION "10.0.26100.0" CACHE STRING "Windows SDK version")
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 10.0)

# Target architecture
if(NOT CMAKE_GENERATOR_PLATFORM)
    set(CMAKE_GENERATOR_PLATFORM x64)
endif()

# Driver configuration
set(TARGET_NAME "AntiCheatDriver")
set(DRIVER_TYPE "KERNEL_MODE")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /RTC-")
string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

# CMake injects the user-mode CRT import libraries (kernel32, user32, ...) into
# every link line. A kernel driver must not resolve against user-mode imports,
# so the defaults are cleared and only WDK kernel libs are linked explicitly.
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(KERNEL_COMPILE_FLAGS
    /kernel
    /D_AMD64_
    /DNTDDI_VERSION=0x0A00000A
    /DWINVER=0x0A00
    /D_WIN32_WINNT=0x0A00
    /GS
    /guard:cf
    /W4
    /WX-
    /O2
    /RTC-
    /Ob2
    /Oi
    /Ot
    /Oy-
    /GL
    /Gz
    /fp:precise
    /Zc:strictStrings
    /Zc:throwingNew
    /Zc:rvalueCast
    /Zc:inline
    /Zc:referenceBinding
    /Zc:__cplusplus
    /Gm-
    /EHsc
    /nologo
    /c
)

# Linker flags for kernel driver
set(KERNEL_LINK_FLAGS
    /SUBSYSTEM:NATIVE,6.01
    /DRIVER:WDM
    /ENTRY:FxDriverEntry
    /NODEFAULTLIB
    /RELEASE
    /OPT:REF
    /OPT:ICF
    /LTCG
    /NXCOMPAT
    /INTEGRITYCHECK
    /SAFESEH:NO
    /MERGE:.rdata=.text
    /MANIFEST:NO
)

add_library(${TARGET_NAME} SHARED
    src/DriverEntry.c
    src/ProcessCallbacks.c
    src/ThreadCallbacks.c
    src/ImageLoadCallbacks.c
    src/DeviceControl.c
    src/MemoryScan.c
    src/DriverUtils.c
    src/AdvancedDetection.c
)

target_compile_options(${TARGET_NAME} PRIVATE ${KERNEL_COMPILE_FLAGS})
target_link_options(${TARGET_NAME} PRIVATE ${KERNEL_LINK_FLAGS})

# KMDF version the binary binds to at load time. It must be <= the WdfLdr/KMDF
# runtime installed on the target host; a higher value makes WdfVersionBind fail
# with STATUS_INVALID_PARAMETER (error 87) and the driver never starts.
set(KMDF_VERSION "1.31" CACHE STRING "KMDF version linked into the driver")

# Link against kernel libraries
set(WDK_LIB_PATH "C:/Program Files (x86)/Windows Kits/10/Lib/${WDK_VERSION}/km/x64")
set(WDF_LIB_PATH "C:/Program Files (x86)/Windows Kits/10/Lib/wdf/kmdf/x64/${KMDF_VERSION}")
target_link_libraries(${TARGET_NAME} PRIVATE
    ${WDK_LIB_PATH}/ntoskrnl.lib
    ${WDK_LIB_PATH}/hal.lib
    ${WDK_LIB_PATH}/wdm.lib
    ${WDK_LIB_PATH}/wdmsec.lib
    ${WDK_LIB_PATH}/ntstrsafe.lib
    ${WDK_LIB_PATH}/libcntpr.lib
    ${WDK_LIB_PATH}/BufferOverflowK.lib
    ${WDF_LIB_PATH}/wdfdriverentry.lib
    ${WDF_LIB_PATH}/wdfldr.lib
)

# Include directories
target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    "C:/Program Files (x86)/Windows Kits/10/Include/${WDK_VERSION}/km"
    "C:/Program Files (x86)/Windows Kits/10/Include/${WDK_VERSION}/km/crt"
    "C:/Program Files (x86)/Windows Kits/10/Include/${WDK_VERSION}/shared"
    "C:/Program Files (x86)/Windows Kits/10/Include/wdf/kmdf/${KMDF_VERSION}"
)

# Output as .sys file
set_target_properties(${TARGET_NAME} PROPERTIES
    OUTPUT_NAME ${TARGET_NAME}
    SUFFIX ".sys"
    PREFIX ""
    LINKER_LANGUAGE C
)

# Optional: sign the driver after build (requires SIGN_CERT and SIGN_PASSWORD)
option(SIGN_DRIVER "Sign the driver with signtool after build" OFF)
if(SIGN_DRIVER)
    find_program(SIGNTOOL signtool)
    if(SIGNTOOL)
        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND ${SIGNTOOL} sign /fd sha256 /a "$<TARGET_FILE:${TARGET_NAME}>"
            COMMENT "Signing driver with signtool"
            VERBATIM)
    endif()
endif()

# Post-build: notify completion
add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Build complete: $<TARGET_FILE:${TARGET_NAME}>"
    COMMENT "Anti-cheat driver built successfully"
    VERBATIM)