include(cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${BASE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

CPMAddPackage("gh:fmtlib/fmt#10.2.1")

set(BOOST_INCLUDE_LIBRARIES "asio")
CPMAddPackage(
        NAME Boost
        VERSION 1.85.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
        OPTIONS "BOOST_SKIP_INSTALL_RULES OFF"
)

set(LIBRARIES "fmt::fmt" "boost_asio")
if (${WIN32})
    add_definitions(-D_WIN32_WINNT=0x0A00)
    list(APPEND LIBRARIES "ws2_32" "wsock32")
endif ()

add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS} $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.11.2")

packageProject(
        NAME ${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        NAMESPACE ${PROJECT_NAMESPACE}
        BINARY_DIR ${PROJECT_BINARY_DIR}
        INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
        INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
        VERSION_HEADER "${PROJECT_NAME}/version.hpp"
        COMPATIBILITY SameMajorVersion
        DEPENDENCIES ${LIBRARIES}
)
