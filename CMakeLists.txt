cmake_minimum_required(VERSION 3.14)

project(libmensago LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Core REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core REQUIRED)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/include)

add_library(mensago SHARED
	include/libmensago.h
	include/base85.h
	include/cryptostring.h
	src/base85.cpp
	src/cryptostring.cpp
)

target_link_libraries(mensago PRIVATE Qt${QT_VERSION_MAJOR}::Core)

target_compile_definitions(mensago PRIVATE LIBMENSAGO_LIBRARY)
