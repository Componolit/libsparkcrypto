theory EC_Tests
imports "$LSC_THYS_DIR/Bignum"
begin

declare [[names_short]]

spark_open "$VCG_DIR/main/ec_tests.siv"

spark_vc procedure_ec_tests_2
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_end


spark_open "$VCG_DIR/main/ec_tests/precompute_values.siv"

spark_vc procedure_precompute_values_1
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_vc procedure_precompute_values_4
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_end


spark_open "$VCG_DIR/main/ec_tests/test_ecdh.siv"

spark_vc function_test_ecdh_1
  by (simp_all del: num_of_lint_update add: num_of_lint_expand)

spark_end


spark_open "$VCG_DIR/main/ec_tests/test_sign.siv"

spark_vc function_test_sign_1
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_vc function_test_sign_2
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_vc function_test_sign_3
  by (simp_all del: num_of_lint_update add: num_of_lint_expand)

spark_vc function_test_sign_4
  by (simp_all del: num_of_lint_update add: num_of_lint_expand)

spark_vc function_test_sign_7
  by (simp del: num_of_lint_update add: num_of_lint_expand)

spark_vc function_test_sign_8
  by (simp_all del: num_of_lint_update add: num_of_lint_expand)

spark_end

end
