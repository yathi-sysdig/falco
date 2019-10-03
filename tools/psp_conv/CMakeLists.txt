add_custom_target(build_falco_psp_conv ALL
	DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/falco-psp-conv)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/falco-psp-conv
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	COMMAND go fmt && go build -o ${CMAKE_CURRENT_BINARY_DIR}/psp_conv)
