cmake_minimum_required(VERSION 3.21)
project(holekeeper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# Qt6 Library
# -----------------------------------------------------------------------------
find_package(Qt6 REQUIRED COMPONENTS Network)
qt_standard_project_setup()
set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} Qt6::Network)

# -----------------------------------------------------------------------------
# Application
# -----------------------------------------------------------------------------
set(PROJECT_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)
qt_add_executable(${PROJECT_NAME}
    src/main.cpp src/peer.cpp src/signal_client.cpp
    src/stun.cpp src/turn.cpp)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_LIBRARIES})
