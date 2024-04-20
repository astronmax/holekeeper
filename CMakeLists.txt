cmake_minimum_required(VERSION 3.21)
project(holekeeper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -----------------------------------------------------------------------------
# Qt6 Library
# -----------------------------------------------------------------------------
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network)
set(PROJECT_LIBRARIES ${PROJECT_LIBRARIES} Qt6::Core Qt6::Network)

# -----------------------------------------------------------------------------
# Application
# -----------------------------------------------------------------------------
set(PROJECT_INCLUDE_DIRS ${PROJECT_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)
file(GLOB_RECURSE PROJECT_SOURCES ${CMAKE_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE PROJECT_INCLUDE_FILES ${CMAKE_SOURCE_DIR}/include/*.hpp)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES} ${PROJECT_INCLUDE_FILES})
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_LIBRARIES})

configure_file(settings.json ${CMAKE_BINARY_DIR} COPYONLY)
