theory lscmnbignum_Lsc__bignum__mod_sub_inplace__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mod_sub_inplace__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  have "0 \<le> num_of_big_int (word32_to_int o a1) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  with `(num_of_big_int' (Array a2 _) _ _ - num_of_big_int' b _ _ = _) = _`
    `carry \<noteq> True` `a = a1`
  show ?thesis by (simp add: base_eq)
qed

why3_end

end
