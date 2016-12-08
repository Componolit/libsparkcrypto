theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using
    `of_int (gcd (uint (p1 * m)) (uint (q1 * m))) = of_int 1`
    `q1 * m = of_int 0`
    `mk_t__ref p2 = mk_t__ref p1`
  by (simp add: word_of_int)

why3_end

end
