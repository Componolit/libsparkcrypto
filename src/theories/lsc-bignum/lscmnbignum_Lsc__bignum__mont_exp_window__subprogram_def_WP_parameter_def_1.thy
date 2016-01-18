theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `a_first < a_last`
    `(_ < num_of_big_int' m _ _) = _`
    `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow> aux1 k = of_int 0`
    `o1 = of_int 1`
  by (simp add: num_of_lint_all0 fun_upd_comp word32_to_int_def)

why3_end

end
