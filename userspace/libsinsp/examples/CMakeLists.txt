include_directories("../../../common")
include_directories("../../")

add_executable(sinsp-example
	util.cpp
	tcp_package_test.cpp
	test.cpp
)

target_link_libraries(sinsp-example
	sinsp
)
