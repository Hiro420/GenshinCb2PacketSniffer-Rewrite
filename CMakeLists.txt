cmake_minimum_required(VERSION 3.12)
project(EnetPacketSnifferDLL)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Where MinHook is located on your system. Edit if needed.
set(MINHOOK_DIR "${CMAKE_SOURCE_DIR}/third_party/minhook")

add_definitions(-DWIN32_LEAN_AND_MEAN)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${MINHOOK_DIR}/include)

file(GLOB SRC
    "src/*.cpp"
)

add_library(EnetSniffer SHARED ${SRC})

# Link MinHook: expects static lib in third_party/minhook/lib/x64 or x86
target_link_libraries(EnetSniffer
    "${MINHOOK_DIR}/lib/x64/MinHook.x64.lib"  # edit path for x86 if needed
)

# If MinHook built as source, you can add it as a subproject or build separately.
