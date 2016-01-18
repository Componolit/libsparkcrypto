theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_43
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_43.xml"

why3_vc WP_parameter_def
  using `mk_int__ref s2 = mk_int__ref s3`
    `s3 < j3` `(math_int_of_int j3 \<le> math_int_from_word i1 + _) = _`
  by simp

why3_end

end
