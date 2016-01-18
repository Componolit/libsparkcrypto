theory lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `o1 \<le> a_last` `\<not> o1 + 1 \<le> a_last`
  have "o1 = a_last" by simp
  with
    `mk_bool__ref True = mk_bool__ref result_us`
    `(result_us = _) = _`
    `(if (if elts a o1 = elts b (b_first + (o1 - a_first)) then _
      else _) \<noteq> _ then _ else _) \<noteq> _`
    `a_first \<le> a_last`
  show ?thesis
    by (simp add: num_of_lint_equals_iff word32_to_int_lower word32_to_int_upper')
qed

why3_end

end
