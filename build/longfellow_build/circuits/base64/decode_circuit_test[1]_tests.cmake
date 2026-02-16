add_test([=[Base64.Circuit]=]  /home/keleigh/zkp-service/build/longfellow_build/circuits/base64/decode_circuit_test [==[--gtest_filter=Base64.Circuit]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Base64.Circuit]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/circuits/base64 SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  decode_circuit_test_TESTS Base64.Circuit)
