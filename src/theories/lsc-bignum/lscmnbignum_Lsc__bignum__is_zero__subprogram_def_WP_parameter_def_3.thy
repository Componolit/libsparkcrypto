theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    num_of_lint_equals_iff [where B="\<lambda>i. 0"]

    `True = (if (if \<lfloor>elts a i1\<rfloor>\<^bsub>w32\<^esub> = 0 then True else False) \<noteq> True then True else False)`
    `(num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat> + 1) = 0) = True`
    `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i1` `i1 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  by (simp add: num_of_lint_all0 word32_to_int_lower word32_to_int_upper'
    del: num_of_lint_sum)

why3_end

end
