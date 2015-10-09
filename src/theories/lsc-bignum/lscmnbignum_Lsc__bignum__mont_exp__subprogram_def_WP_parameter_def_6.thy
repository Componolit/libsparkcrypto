theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux2 _) aux2_first (a_last - a_first + 1) = _) = _`
    `(_ < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
