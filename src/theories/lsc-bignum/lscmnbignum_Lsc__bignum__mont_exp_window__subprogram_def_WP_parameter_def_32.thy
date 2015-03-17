theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_32
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_32.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>o1\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o2\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat>`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
  have "\<lfloor>o1\<rfloor>\<^bsub>w64\<^esub> + 1 = (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) * 32"
    by (simp add: emod_def mod_pos_pos_trivial)
  with
    `(num_of_big_int' (Array aux3 _) _ _ = _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
  show ?thesis
    by (simp only: nat_mult_distrib base_eq)
      (simp add: power_mult mult.commute [of _ 32]
         num_of_lint_lower num_of_lint_upper word32_to_int_lower word32_to_int_upper'
         div_pos_pos_trivial del: num_of_lint_sum)
qed

why3_end

end
