theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
    aux1 k = of_int 0`
    `a_first < a_last` `o1 = _`
  show ?thesis by (simp add: num_of_lint_all0 fun_upd_comp word32_to_int_def)
qed

why3_end

end
