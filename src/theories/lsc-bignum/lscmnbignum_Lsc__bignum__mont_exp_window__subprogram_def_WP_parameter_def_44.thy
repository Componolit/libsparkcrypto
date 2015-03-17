theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_44
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_44.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o12\<rfloor>\<^sub>\<nat> = \<lfloor>j\<rfloor>\<^sub>\<nat> + 1`
    `(if (if \<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat> then _ else _) \<noteq> _ then _ else _) \<noteq> _`
    `\<lfloor>o6\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>j\<rfloor>\<^sub>\<nat>`
  by simp

why3_end

end
