include(cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${BASE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

CPMAddPackage("gh:fmtlib/fmt#10.2.1")
CPMAddPackage(
        NAME asio
        GITHUB_REPOSITORY chriskohlhoff/asio
        GIT_TAG asio-1-30-2
        DOWNLOAD_ONLY yes
)

set(LIBRARIES "fmt::fmt")
if (${WIN32})
    add_definitions(-D_WIN32_WINNT=0x0A00)
    list(APPEND LIBRARIES "ws2_32" "wsock32")
endif ()

add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>)

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
        DEPENDENCIES ${DEPENDENCIES}
)
