cmake_minimum_required(VERSION 3.5)

project(untitled LANGUAGES C)

add_executable(untitled main.c base64.h base64.c uuid.h uuid.c secret.h secret.c)
target_link_libraries(untitled -lgpgme -lgcrypt -luuid)

install(TARGETS untitled
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
