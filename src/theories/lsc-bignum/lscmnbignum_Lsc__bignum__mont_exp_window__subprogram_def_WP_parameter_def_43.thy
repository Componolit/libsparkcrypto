theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_43
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_43.xml"

why3_vc WP_parameter_def
  using `\<lfloor>o7\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>shl32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> OR 1`
  by (simp add: mod_def emod_def AND_mod [where n=1, simplified, symmetric])

why3_end

end
