theory lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `result1 \<le> a_last` `\<not> result1 + 1 \<le> a_last`
  have "result1 = a_last" by simp
  with
    `lsc__bignum__equal__result = True`
    `lsc__bignum__equal__result = result_us`
    `mk_bool__ref result_us = mk_bool__ref result_us1`
    `result_us1 = result_us2`
    `(result_us2 = _) = _`
    `(if (if elts a result1 = elts b (b_first + (result1 - a_first)) then _
      else _) \<noteq> _ then _ else _) \<noteq> _`
    `a_first \<le> a_last`
  show ?thesis
    by (simp add: num_of_lint_equals_iff word32_to_int_lower word32_to_int_upper')
qed

why3_end

end
