add_executable(miniedr
  src/main.cpp
  src/collectors/sysmon_collector.cpp
  src/collectors/driver_collector.cpp
  src/response/apihook_responder.cpp
  src/hooking/apihook_injector.cpp
  src/collectors/api_hook_collector.cpp
  src/enrich/process_enricher.cpp
  src/driver/driver_policy.cpp
  src/driver/signer_trust.cpp
  src/collectors/etw_kernel_collector.cpp
  src/pipeline/normalizer.cpp
  src/detection/rule_engine.cpp
  src/detection/correlator.cpp
  src/output/alert_sinks.cpp
  src/utils/win_path.cpp
  src/utils/encoding.cpp
  src/scanners/process_runner.cpp
  src/scanners/scanner_manager.cpp
  src/scanners/pe_sieve_adapter.cpp
  src/scanners/hollows_hunter_adapter.cpp
  src/utils/xml_event_parser.cpp
  src/scanners/yara/yara_adapter.cpp
  src/response/response_manager.cpp
  src/response/process_responder.cpp
)

target_include_directories(miniedr PRIVATE src ../driver/include)

if (WIN32)
  target_link_libraries(miniedr PRIVATE wevtapi advapi32 tdh xmllite crypt32 wintrust bcrypt)
  target_compile_definitions(miniedr PRIVATE UNICODE _UNICODE)
endif()

# Optional: place output in a predictable folder
set_target_properties(miniedr PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
