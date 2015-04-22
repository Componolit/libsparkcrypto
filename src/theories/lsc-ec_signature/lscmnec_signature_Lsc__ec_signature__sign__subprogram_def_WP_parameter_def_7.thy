theory lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_7
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_7.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>sign1_last1\<rfloor>\<^sub>\<nat> - \<lfloor>sign1_first1\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a1 _) _ _ = _) = _`
    `(1 < num_of_big_int' n _ _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq less_imp_le [OF pos_mod_bound])

why3_end

end
