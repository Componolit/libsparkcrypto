theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_49
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_49.xml"

why3_vc WP_parameter_def
  using `\<lfloor>r224b\<rfloor>\<^sub>\<nat> = \<lfloor>s\<rfloor>\<^sub>\<nat> + 1` `mk_ref s = mk_ref s1`
    `\<lfloor>s1\<rfloor>\<^sub>\<nat> < \<lfloor>j1\<rfloor>\<^sub>\<nat>` `(\<lfloor>j1\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> + 1) = _`
  by simp

why3_end

end
