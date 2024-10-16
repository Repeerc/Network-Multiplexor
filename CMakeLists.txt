cmake_minimum_required (VERSION 3.6)
project (c_tap)

include_directories(npcap/Include)
link_directories(npcap/Lib/x64)

file(GLOB SOURCES *.h *.c)
add_executable(${PROJECT_NAME} ${SOURCES})
target_compile_options(${PROJECT_NAME} PRIVATE -Ofast -Wall -DNDEBUG -mavx -mavx2)
 
target_link_libraries(${PROJECT_NAME} -static pthread ws2_32 iphlpapi wpcap.lib -mavx -mavx2)

