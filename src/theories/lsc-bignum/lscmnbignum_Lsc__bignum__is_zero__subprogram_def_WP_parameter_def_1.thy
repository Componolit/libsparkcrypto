theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `mk_bool__ref True = mk_bool__ref result_us1`
    `(result_us1 = True) = _`
    `(if (if elts a a_last = _ then True else False) \<noteq> True then True else False) \<noteq> True`
    `a_first \<le> a_last`
  by (simp add: num_of_lint_all0 word32_to_int_def)

why3_end

end
