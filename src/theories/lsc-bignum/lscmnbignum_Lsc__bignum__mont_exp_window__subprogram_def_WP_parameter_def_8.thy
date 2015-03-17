theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_8
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
  using
    `\<forall>k. \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> + \<lfloor>o1\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>aux1 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>` `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = 1`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  by (simp add: fun_upd_comp num_of_lint_all0)

why3_end

end
