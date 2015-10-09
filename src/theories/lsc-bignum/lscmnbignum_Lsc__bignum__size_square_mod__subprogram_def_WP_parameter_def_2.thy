theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using `(num_of_big_int' (Array r _) _ _ = _) = _`
  by simp

why3_end

end
