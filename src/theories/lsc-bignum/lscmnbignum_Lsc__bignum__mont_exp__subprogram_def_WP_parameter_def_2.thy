theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `(1 < num_of_big_int' m _ _) = _`
    `(num_of_big_int' r _ _ = _) = _`
  by simp

why3_end

end
