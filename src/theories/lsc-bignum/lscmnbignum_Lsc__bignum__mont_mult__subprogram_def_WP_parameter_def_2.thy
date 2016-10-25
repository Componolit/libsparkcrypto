theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `\<forall>k. a_first \<le> k \<and> k \<le> a_last \<longrightarrow> a k = of_int 0`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = True`
  by (simp add: num_of_lint_all0 word32_to_int_def)

why3_end

end
