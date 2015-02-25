theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
