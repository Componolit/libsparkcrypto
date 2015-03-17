theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_22
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_22.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux2 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  by simp

why3_end

end
