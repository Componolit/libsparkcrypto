theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_8
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
  using
    `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow> aux1 k = of_int 0`
    `o1 = of_int 1`
    `a_first < a_last`
  by (simp add: fun_upd_comp num_of_lint_all0 word32_to_int_def)

why3_end

end
