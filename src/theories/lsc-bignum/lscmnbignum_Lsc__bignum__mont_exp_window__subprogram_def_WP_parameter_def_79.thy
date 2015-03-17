theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_79
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_79.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `\<lfloor>o5\<rfloor>\<^bsub>w64\<^esub> = (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>o4\<rfloor>\<^bsub>w64\<^esub>) emod _`
    `\<lfloor>o4\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>s\<rfloor>\<^sub>\<nat>`
    `\<lfloor>o3\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>s\<rfloor>\<^sub>\<nat>`
    `(if \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < \<lfloor>o3\<rfloor>\<^bsub>w64\<^esub> then _ else _) \<noteq> _`
    word64_to_int_upper [of i]
    natural_to_int_lower [of s]
  by (simp add: emod_def mod_pos_pos_trivial)

why3_end

end
