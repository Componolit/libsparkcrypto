theory EC_Signature
imports Bignum
begin

declare [[names_short]]

spark_open "$VCG_DIR/lsc_/ec_signature/extract.siv" (lsc__ec_signature)

spark_vc procedure_extract_2
  using `num_of_big_int rm _ _ = _`
  by simp

spark_vc procedure_extract_4
  using
    `1 < num_of_big_int n _ _`
    `x_first < x_last`
  by (simp add: num_of_lint_all0)

spark_vc procedure_extract_5
  using
    `num_of_big_int rn _ _ = _`
    `1 < num_of_big_int n _ _`
  by (simp add: sign_simps)

spark_vc procedure_extract_6
  using
    `num_of_big_int v__4 _ _ = _`
    `1 < num_of_big_int n _ _`
  by simp

spark_end


spark_open "$VCG_DIR/lsc_/ec_signature/sign.siv" (lsc__ec_signature)

spark_vc procedure_sign_2
  using
    `1 < num_of_big_int m _ _`
    `sign1_first < sign1_last`
  by (simp add: num_of_lint_all0)

spark_vc procedure_sign_7
  using `num_of_big_int rn _ _ = _`
  by simp

spark_vc procedure_sign_12
  using
    `num_of_big_int privr__3 _ _ = _`
    `1 < num_of_big_int n _ _`
  by (simp add: sign_simps)

spark_vc procedure_sign_17
  using
    `lsc__bignum__is_zero sign1__2 _ _ = _`
    `bounds _ _ _ _ sign1__2`
    `num_of_big_int sign1__2 _ _ < num_of_big_int n _ _`
    `_ \<longrightarrow> lsc__bignum__is_zero sign2__7 _ _ = _`
    `num_of_big_int sign2__7 _ _ = _`
    `1 < num_of_big_int n _ _`
    `sign1__index__subtype__1__first \<le> sign1_first`
    `sign1_last \<le> sign1__index__subtype__1__last`
  by (simp add: num_of_lint_lower less_le [of 0] cong add: conj_cong)

spark_vc procedure_sign_18
  using
    `lsc__bignum__is_zero sign1__2 _ _ = _`
    `bounds _ _ _ _ sign1__2`
    `num_of_big_int sign1__2 _ _ < num_of_big_int n _ _`
    `_ \<longrightarrow> lsc__bignum__is_zero sign2__11 _ _ = _`
    `num_of_big_int sign2__11 _ _ = _`
    `1 < num_of_big_int n _ _`
    `sign1__index__subtype__1__first \<le> sign1_first`
    `sign1_last \<le> sign1__index__subtype__1__last`
  by (simp add: num_of_lint_lower less_le [of 0] cong add: conj_cong)

spark_end


spark_open "$VCG_DIR/lsc_/ec_signature/verify.siv" (lsc__ec_signature)

spark_vc function_verify_4
  using
    `sign2__index__subtype__1__first \<le> sign2_first`
    `sign2_first + (sign1_last - sign1_first) \<le> sign2__index__subtype__1__last`
    `sign1_first < sign1_last`
  by simp

spark_vc function_verify_5
  using
    `sign2__index__subtype__1__first \<le> sign2_first`
    `sign2_first + (sign1_last - sign1_first) \<le> sign2__index__subtype__1__last`
    `n__index__subtype__1__first \<le> n_first`
    `n_first + (sign1_last - sign1_first) \<le> n__index__subtype__1__last`
    `sign1_first < sign1_last`
  by simp

spark_vc function_verify_6
  using `num_of_big_int rn _ _ = _`
  by simp

spark_vc function_verify_12
  using
    `1 < num_of_big_int m _ _`
    `sign1_first < sign1_last`
  by (simp add: num_of_lint_all0)

spark_vc function_verify_13
  using
    `1 < num_of_big_int m _ _`
    `sign1_first < sign1_last`
  by (simp add: num_of_lint_all0)

spark_end

end
