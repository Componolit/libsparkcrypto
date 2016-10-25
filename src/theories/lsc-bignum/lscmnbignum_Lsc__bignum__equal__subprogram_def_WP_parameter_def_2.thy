theory lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `mk_bool__ref result_us = mk_bool__ref result_us1`
    `(result_us1 = _) = _`
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
  by (simp add: num_of_lint_equals_iff uint_lt [where 'a=32, simplified]
    word32_to_int_def del: num_of_lint_sum)

why3_end

end
