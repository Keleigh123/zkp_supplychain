add_test([=[Interpolation.Simple]=]  /home/keleigh/zkp-service/build/longfellow_build/algebra/interpolation_test [==[--gtest_filter=Interpolation.Simple]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[Interpolation.Simple]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/algebra SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  interpolation_test_TESTS Interpolation.Simple)
