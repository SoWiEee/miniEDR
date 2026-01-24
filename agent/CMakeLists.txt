add_executable(miniedr
  src/main.cpp
  src/collectors/sysmon_collector.cpp
  src/pipeline/normalizer.cpp
  src/detection/rule_engine.cpp
  src/output/alert_sinks.cpp
)

target_include_directories(miniedr PRIVATE src)

if (WIN32)
  target_link_libraries(miniedr PRIVATE wevtapi)
  target_compile_definitions(miniedr PRIVATE UNICODE _UNICODE)
endif()

# Optional: place output in a predictable folder
set_target_properties(miniedr PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
