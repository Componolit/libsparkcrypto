theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
  using `of_int (gcd (uint (result4 * m)) (uint (result5 * m))) = of_int 1`
  by (simp add: gcd_red_int [symmetric] uint_mod)

why3_end

end
