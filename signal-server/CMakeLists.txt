cmake_minimum_required(VERSION 3.21)
project(signal_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# Boost Library
# -----------------------------------------------------------------------------
set(Boost_USE_STATIC_LIBS ON)
set(Boost_DEBUG OFF)
find_package(Boost 1.65 REQUIRED)

if(Boost_FOUND)
    set(PROJECT_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS})
    set(PROJECT_LIBRARIES ${PROJECT_LINK_LIBRARIES} ${Boost_LIBRARIES})
else()
    message(SEND_ERROR "Boost library not found")
endif()

# -----------------------------------------------------------------------------
# Spdlog Library
# -----------------------------------------------------------------------------
add_subdirectory(${CMAKE_SOURCE_DIR}/spdlog)
set(PROJECT_LIBRARIES ${PROJECT_LINK_LIBRARIES} spdlog)
set(PROJECT_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/spdlog/include)

# -----------------------------------------------------------------------------
# Application
# -----------------------------------------------------------------------------
file(GLOB_RECURSE PROJECT_SOURCE_FILES ${CMAKE_SOURCE_DIR}/src/*.cpp)
add_executable(${PROJECT_NAME} ${PROJECT_SOURCE_FILES})
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_LIBRARIES} -static)
