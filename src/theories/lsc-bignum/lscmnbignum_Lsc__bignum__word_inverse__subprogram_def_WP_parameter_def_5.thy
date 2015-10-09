theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using
    `lsc__bignum__word_inverse__result = of_int 0 - p`
    `of_int (gcd (uint a2) (uint (of_int 0))) = of_int 1`
    `a2 = p2 * m`
    `of_int 0 = b2`
    `mk_t__ref p = mk_t__ref p2`
  by (simp add: word_of_int)

why3_end

end
