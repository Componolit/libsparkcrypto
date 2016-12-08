theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    num_of_lint_equals_iff [where B="\<lambda>i. 0"]
    `(if (if elts a o1 = _ then True else False) \<noteq> True then True else False) = _`
    `(num_of_big_int' a a_first (a_last - a_first + 1) = _) = True`
    `a_first \<le> o1` `o1 \<le> a_last`
  by (simp add: num_of_lint_all0
    word32_to_int_def uint_lt [where 'a=32, simplified] uint_0_iff
    del: num_of_lint_sum)

why3_end

end
