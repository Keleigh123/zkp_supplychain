add_test([=[Counter.Fields]=]  /home/keleigh/zkp-service/build/longfellow_build/circuits/logic/counter_test [==[--gtest_filter=Counter.Fields]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Counter.Fields]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/circuits/logic SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  counter_test_TESTS Counter.Fields)
