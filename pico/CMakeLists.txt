# CMake for the RP2040 inspector firmware. Requires the Pico SDK.
# The SDK is deliberately NOT bundled or fetched: set PICO_SDK_PATH yourself.
cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED PICO_SDK_PATH OR NOT EXISTS "${PICO_SDK_PATH}/pico_sdk_init.cmake")
    message(FATAL_ERROR
        "Pico SDK not found. Set PICO_SDK_PATH to a checkout containing "
        "pico_sdk_init.cmake; the SDK is not vendored in this repository.")
endif()

include("${PICO_SDK_PATH}/pico_sdk_init.cmake")

project(cbm_pico_inspector C CXX ASM)
pico_sdk_init()

add_executable(cbm_pico_inspector
    firmware.c
    tea_core.c
    inspector.c
)
target_include_directories(cbm_pico_inspector PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(cbm_pico_inspector pico_stdlib hardware_gpio)

# Console over USB serial; the board never writes to the inspected source.
pico_enable_stdio_usb(cbm_pico_inspector 1)
pico_enable_stdio_uart(cbm_pico_inspector 0)
pico_add_extra_outputs(cbm_pico_inspector)
