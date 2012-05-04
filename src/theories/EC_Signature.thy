theory EC_Signature
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec_signature/extract.siv" (lsc__ec_signature)

spark_vc procedure_extract_3
  using `1 < num_of_big_int n _ _`
  by (simp add: num_of_lint_all0)

spark_end


spark_open "$VCG_DIR/lsc_/ec_signature/sign.siv" (lsc__ec_signature)

spark_vc procedure_sign_1
  using `1 < num_of_big_int m _ _`
  by (simp add: num_of_lint_all0)

spark_vc procedure_sign_16
  using
    `lsc__bignum__is_zero sign1__2 _ _ = _`
    `bounds _ _ _ _ sign1__2`
    `num_of_big_int sign1__2 _ _ < num_of_big_int n _ _`
    `_ \<longrightarrow> lsc__bignum__is_zero sign2__7 _ _ = _`
    `num_of_big_int sign2__7 _ _ = _`
    `1 < num_of_big_int n _ _`
  by (simp add: num_of_lint_lower less_le [of 0] cong add: conj_cong)

spark_vc procedure_sign_17
  using
    `lsc__bignum__is_zero sign1__2 _ _ = _`
    `bounds _ _ _ _ sign1__2`
    `num_of_big_int sign1__2 _ _ < num_of_big_int n _ _`
    `_ \<longrightarrow> lsc__bignum__is_zero sign2__11 _ _ = _`
    `num_of_big_int sign2__11 _ _ = _`
    `1 < num_of_big_int n _ _`
  by (simp add: num_of_lint_lower less_le [of 0] cong add: conj_cong)

spark_end


spark_open "$VCG_DIR/lsc_/ec_signature/verify.siv" (lsc__ec_signature)

spark_vc function_verify_11
  using `1 < num_of_big_int m _ _`
  by (simp add: num_of_lint_all0)

spark_vc function_verify_12
  using `1 < num_of_big_int m _ _`
  by (simp add: num_of_lint_all0)

spark_end

end
