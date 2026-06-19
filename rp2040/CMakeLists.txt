# RP2040 USB multi-peripheral descriptor/behaviour fuzzer
#
# Build (with PICO_SDK_PATH exported):
#   mkdir build && cd build
#   cmake .. -DPICO_BOARD=pico
#   make -j
#
# Output: rp2040_usb_fuzz.uf2  (drag onto the RPI-RP2 mass-storage boot volume)
#
# Logs come out over UART0 (GP0/GP1) at 115200 8N1, NOT over USB, because the
# native USB port is the device-under-test surface presented to the target host.

cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(rp2040_usb_fuzz C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(rp2040_usb_fuzz
    src/main.c
    src/fuzz.c
    src/usb_descriptors.c
    src/usb_callbacks.c
)

# tusb_config.h lives in include/
target_include_directories(rp2040_usb_fuzz PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/src
)

target_link_libraries(rp2040_usb_fuzz
    pico_stdlib
    tinyusb_device
    tinyusb_board
    hardware_flash
    hardware_sync
    hardware_watchdog
)

# Logs over UART, NOT USB: the USB port is the fuzz surface.
pico_enable_stdio_uart(rp2040_usb_fuzz 1)
pico_enable_stdio_usb(rp2040_usb_fuzz 0)

pico_add_extra_outputs(rp2040_usb_fuzz)
