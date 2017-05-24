theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_44
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_44.xml"

why3_vc WP_parameter_def
  using `s2 < j2` `(math_int_of_int j2 \<le> math_int_from_word i + _) = _`
  by (simp add: int__content_def)

why3_end

end
