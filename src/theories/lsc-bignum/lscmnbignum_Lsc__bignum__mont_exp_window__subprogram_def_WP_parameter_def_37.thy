theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_37
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_37.xml"

why3_vc WP_parameter_def
proof -
  from
    `\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) emod _ * 32 emod _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
  have i: "int (nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>) < 32 * (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: emod_def mod_pos_pos_trivial)

  from
    `\<lfloor>o3\<rfloor>\<^bsub>w32\<^esub> = 1` `\<lfloor>o4\<rfloor>\<^sub>\<nat> = 0` `\<lfloor>o5\<rfloor>\<^sub>\<nat> = 1`
    `bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> = True`
    `(bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> = True) = _`
  show ?thesis
    by (simp add: num_of_lint_lower AND_div_mod [symmetric] mod_eq_1
      num_of_lint_AND_32 [OF i] zdiv_int nat_mod_distrib mod_def
      emod_def ediv_def
      word32_to_int_lower  word32_to_int_upper' word64_to_int_lower)
qed

why3_end

end
