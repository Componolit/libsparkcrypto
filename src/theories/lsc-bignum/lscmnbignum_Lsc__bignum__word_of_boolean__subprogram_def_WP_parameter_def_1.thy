theory lscmnbignum_Lsc__bignum__word_of_boolean__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_of_boolean__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `lsc__bignum__word_of_boolean__result = result_us`
    `result_us = of_int 0`
    `b \<noteq> True`
  by simp

why3_end

end
