cmake_minimum_required (VERSION 2.8.13)

SET(COMMIT_HASH "test" CACHE STRING "Project build info")
message("COMMIT_HASH=${COMMIT_HASH}")

project (disasm-cli)
find_package(Qt5Core REQUIRED)

include_directories ( ${PARSER_INC} )
include_directories ( ${MINIDIS_DIR}/include )

set ( srcs
    main.cpp
)

set ( hdrs
    main.h
)

QT5_WRAP_CPP (hdrs_moc ${hdrs})

add_definitions(-DCOMMIT_HASH=${COMMIT_HASH})

add_executable (${PROJECT_NAME} ${srcs} ${hdrs} )

if (USE_UDIS86)
    target_link_libraries (${PROJECT_NAME} ${MINIDIS_LIB} ${PARSER_LIB} ${UDIS86_LIB} Qt5::Core Qt5::Widgets )
    MESSAGE( "Compiling using udis86" )
else()
    target_link_libraries (${PROJECT_NAME} ${MINIDIS_LIB} ${PARSER_LIB} ${CAPSTONE_LIB} Qt5::Core )
    MESSAGE( "Compiling using capstone" )
endif()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})


#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )


