add_test([=[LCH14.ReedSolomon]=]  /home/keleigh/zkp-service/build/longfellow_build/gf2k/lch14_reed_solomon_test [==[--gtest_filter=LCH14.ReedSolomon]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[LCH14.ReedSolomon]=]  PROPERTIES WORKING_DIRECTORY /home/keleigh/zkp-service/build/longfellow_build/gf2k SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  lch14_reed_solomon_test_TESTS LCH14.ReedSolomon)
