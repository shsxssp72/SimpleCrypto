cmake_minimum_required(VERSION 3.9)
project(Crypto)

set(CMAKE_CXX_STANDARD 17)
link_libraries(C:/CppLibrary/cryptopp565_clang/lib/libcryptopp_Release.a)
add_executable(Crypto main.cpp KeyGeneratorWrapper.h KeyGeneratorWrapper.cpp BaseWrapper.h)