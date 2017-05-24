theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using
    `of_int (gcd (uint (p * m)) (uint (q * m))) = of_int 1`
    `q * m = of_int 0`
  by (simp add: word_of_int t__content_def)

why3_end

end
