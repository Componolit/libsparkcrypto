theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_81
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_81.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux1 _) _ _ = 1) = _`
    `(1 < num_of_big_int' m _ _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  by simp

why3_end

end
