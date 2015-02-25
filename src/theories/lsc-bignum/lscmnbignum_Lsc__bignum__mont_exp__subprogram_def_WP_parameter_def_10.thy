theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_10
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_10.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array (aux1(\<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> := o1)) _) _ _ = 1) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
