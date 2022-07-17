cmake_minimum_required (VERSION 3.0)

SET(COMMIT_HASH "test" CACHE STRING "Project build info")
message("COMMIT_HASH=${COMMIT_HASH}")

project (disasm-cli)
find_package(Qt5Core REQUIRED)

include_directories ( ${PARSER_INC} )
include_directories ( ${MINIDIS_DIR}/include )

if(USE_QT4)
	add_compile_definitions(WITH_QT4)
	find_package (Qt4 REQUIRED)
	include_directories( ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} )
	INCLUDE( ${QT_USE_FILE} )
	ADD_DEFINITIONS( ${QT_DEFINITIONS} )
else()
	add_compile_definitions(WITH_QT5)
	find_package(Qt5Core REQUIRED)
	get_target_property(QtCore_location Qt5::Core LOCATION)
endif()

set ( srcs
    main.cpp
)

set ( hdrs
    main.h
)

add_definitions(-DCOMMIT_HASH=${COMMIT_HASH})

add_executable (${PROJECT_NAME} ${srcs} ${hdrs} )

if(USE_QT4)
    target_link_libraries ( ${PROJECT_NAME} ${QT_QTCORE_LIBRARIES} )
else()
    target_link_libraries( ${PROJECT_NAME} Qt5::Core)
endif()


if (USE_UDIS86)
    target_link_libraries (${PROJECT_NAME} ${MINIDIS_LIB} ${PARSER_LIB} ${UDIS86_LIB})
    MESSAGE( "Compiling using udis86" )
else()
    target_link_libraries (${PROJECT_NAME} ${MINIDIS_LIB} ${PARSER_LIB} ${CAPSTONE_LIB})
    MESSAGE( "Compiling using capstone" )
endif()

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})


#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )


