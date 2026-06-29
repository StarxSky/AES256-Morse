cmake_minimum_required(VERSION 3.14)
project(aes256-oii VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(oiienc src/oiienc.cpp)
target_link_libraries(oiienc PRIVATE OpenSSL::Crypto)

add_executable(oiidec src/oiidec.cpp)
target_link_libraries(oiidec PRIVATE OpenSSL::Crypto)
