add_test([=[mdoc.mdoc_small_test]=]  /home/keleigh/zkp-service/build/longfellow_build/circuits/anoncred/small_test [==[--gtest_filter=mdoc.mdoc_small_test]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[mdoc.mdoc_small_test]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/circuits/anoncred SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  small_test_TESTS mdoc.mdoc_small_test)
