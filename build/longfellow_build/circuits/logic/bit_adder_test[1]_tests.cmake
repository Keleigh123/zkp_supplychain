add_test([=[BitAdder.Fields]=]  /home/keleigh/zkp-service/build/longfellow_build/circuits/logic/bit_adder_test [==[--gtest_filter=BitAdder.Fields]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[BitAdder.Fields]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/circuits/logic SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  bit_adder_test_TESTS BitAdder.Fields)
