theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_36
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_36.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) emod _ * 32 emod _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    `\<lfloor>e_last\<rfloor>\<^sub>\<nat> \<le> \<lfloor>snd (rt e)\<rfloor>\<^sub>\<int>`
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
  by (simp add: ediv_def emod_def mod_pos_pos_trivial)

why3_end

end
