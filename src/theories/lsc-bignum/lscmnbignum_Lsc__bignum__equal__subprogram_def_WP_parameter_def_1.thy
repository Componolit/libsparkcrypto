theory lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__equal__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `i2 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>` `\<not> i2 + 1 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  have "i2 = \<lfloor>a_last\<rfloor>\<^sub>\<nat>" by simp
  with
    `lsc__bignum__equal__result = True`
    `lsc__bignum__equal__result = result_us`
    `mk_ref result_us = mk_ref result_us1`
    `result_us1 = result_us2`
    `(result_us2 = _) = _`
    `(if (if \<lfloor>elts a i2\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i2 - \<lfloor>a_first\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> then _
      else _) \<noteq> _ then _ else _) \<noteq> _`
    `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  show ?thesis
    by (simp add: num_of_lint_equals_iff word32_to_int_lower word32_to_int_upper')
qed

why3_end

end
