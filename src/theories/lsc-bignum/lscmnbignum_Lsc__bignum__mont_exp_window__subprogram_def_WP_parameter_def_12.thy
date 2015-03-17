theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_12
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_12.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux4 _) _ _ = _) = _`
    `0 \<le> n` `n \<le> 1 - 1`
  by simp

why3_end

end
