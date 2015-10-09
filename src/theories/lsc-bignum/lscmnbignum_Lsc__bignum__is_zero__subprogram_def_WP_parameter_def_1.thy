theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `\<not> result1 + 1 \<le> a_last` `result1 \<le> a_last`
  have "result1 = a_last" by simp
  with
    `lsc__bignum__is_zero__result = True`
    `lsc__bignum__is_zero__result = result_us`
    `mk_bool__ref result_us = mk_bool__ref result_us1`
    `result_us1 = result_us2`
    `(result_us2 = True) = _`
    `(if (if elts a result1 = _ then True else False) \<noteq> True then True else False) \<noteq> True`
    `a_first \<le> a_last`
  show ?thesis
    by (simp add: num_of_lint_all0 word32_to_int_def)
qed

why3_end

end
