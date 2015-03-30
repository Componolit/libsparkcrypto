theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    num_of_lint_equals_iff [where B="\<lambda>i. 0"]
    `lsc__bignum__is_zero__result = result_us`
    `mk_ref result_us = mk_ref result_us1`
    `result_us1 = result_us2`
    `(result_us2 = True) = _`
    `(num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat> + 1) = 0) = _`
    `(if (if \<lfloor>elts a i2\<rfloor>\<^bsub>w32\<^esub> = 0 then _ else _) \<noteq> _ then _ else _) \<noteq> _`
    `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i2` `i2 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  by (simp add: num_of_lint_all0 word32_to_int_lower word32_to_int_upper'
    del: num_of_lint_sum)

why3_end

end
