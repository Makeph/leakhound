cmake_minimum_required(VERSION 3.15)
project(leakhound LANGUAGES CXX)

add_executable(leakhound src/leakhound.cpp)
target_compile_features(leakhound PRIVATE cxx_std_17)
set_target_properties(leakhound PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

if(MSVC)
    target_compile_options(leakhound PRIVATE /W4)
else()
    target_compile_options(leakhound PRIVATE -Wall -Wextra)
endif()
