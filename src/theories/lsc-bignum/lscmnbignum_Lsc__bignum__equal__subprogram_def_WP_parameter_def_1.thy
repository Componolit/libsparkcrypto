theory lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `mk_bool__ref True = mk_bool__ref result_us1`
    `(result_us1 = _) = _`
    `(if (if elts a a_last = elts b (b_first + (a_last - a_first)) then _
      else _) \<noteq> _ then _ else _) \<noteq> _`
    `a_first \<le> a_last`
  by (simp add: num_of_lint_equals_iff word32_to_int_lower word32_to_int_upper')

why3_end

end
