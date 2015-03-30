theory lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__is_zero__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `\<not> i2 + 1 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>` `i2 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  have "i2 = \<lfloor>a_last\<rfloor>\<^sub>\<nat>" by simp
  with
    `lsc__bignum__is_zero__result = True`
    `lsc__bignum__is_zero__result = result_us`
    `mk_ref result_us = mk_ref result_us1`
    `result_us1 = result_us2`
    `(result_us2 = True) = _`
    `(if (if \<lfloor>elts a i2\<rfloor>\<^bsub>w32\<^esub> = 0 then True else False) \<noteq> True then True else False) \<noteq> True`
    `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  show ?thesis
    by (simp add: num_of_lint_all0)
qed

why3_end

end
