cmake_minimum_required(VERSION 3.14)

set(CMAKE_C_COMPILER "gcc-11")
set(CMAKE_CXX_COMPILER "g++-11")

project(chans LANGUAGES C CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core LinguistTools)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core LinguistTools)

set(TS_FILES chans_en_001.ts)

add_executable(chans
  main.cpp
  chunker.h
  chunker.cpp
  secret.h
  secret.cpp
  keyring.h
  keyring.cpp
  ${TS_FILES}
)
target_link_libraries(chans Qt${QT_VERSION_MAJOR}::Core)
target_link_libraries(chans -lgpgme)

if(COMMAND qt_create_translation)
    qt_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
else()
    qt5_create_translation(QM_FILES ${CMAKE_SOURCE_DIR} ${TS_FILES})
endif()

install(TARGETS chans
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
