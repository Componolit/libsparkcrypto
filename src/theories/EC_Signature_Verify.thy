theory EC_Signature_Verify
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec_/signature/verify.siv" (lsc__ec__signature)

spark_vc function_verify_11
  using `1 < num_of_big_int m _ _`
  by (simp add: num_of_lint_all0)

spark_vc function_verify_12
  using `1 < num_of_big_int m _ _`
  by (simp add: num_of_lint_all0)

spark_end

end
