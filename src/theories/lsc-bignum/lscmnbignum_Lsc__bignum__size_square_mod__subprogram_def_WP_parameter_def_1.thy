theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `o1 = _`
    `\<forall>k. _ \<longrightarrow> r k = _`
    `m_first \<le> m_last`
    `(_ < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0 mod_pos_pos_trivial fun_upd_comp word32_to_int_def
    del: num_of_lint_sum)

why3_end

end
