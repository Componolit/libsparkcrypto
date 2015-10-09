theory lscmnbignum_Lsc__bignum__mod_sub__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mod_sub__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  let ?k = "a_last - a_first + 1"
  have "0 \<le> num_of_big_int' b b_first ?k"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  with
    `(num_of_big_int' c _ _ \<le> num_of_big_int' m _ _) = _`
    `(num_of_big_int' b _ _ - num_of_big_int' c _ _ = _) = _`
  have "Base ^ nat ?k \<le>
    num_of_big_int (word32_to_int o a) a_first ?k + int_of_math_int (num_of_big_int' m m_first ?k)"
    by (simp add: base_eq)
  moreover have "num_of_big_int (word32_to_int o a) a_first ?k < Base ^ nat ?k"
    "num_of_big_int (word32_to_int o a1) a_first ?k < Base ^ nat ?k"
    by (simp_all add: num_of_lint_upper word32_to_int_upper')
  ultimately show ?thesis
  using
    `(num_of_big_int' b _ _ - num_of_big_int' c _ _ = _) = _`
    `(num_of_big_int' (Array a _) _ _ + num_of_big_int' m _ _ = _) = _`
    by (cases carry) (simp_all add: base_eq)
qed

why3_end

end
