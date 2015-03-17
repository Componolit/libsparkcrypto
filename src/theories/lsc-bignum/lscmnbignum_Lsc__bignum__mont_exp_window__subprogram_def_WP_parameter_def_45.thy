theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_45
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_45.xml"

why3_vc WP_parameter_def
  using `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
  by simp

why3_end

end
