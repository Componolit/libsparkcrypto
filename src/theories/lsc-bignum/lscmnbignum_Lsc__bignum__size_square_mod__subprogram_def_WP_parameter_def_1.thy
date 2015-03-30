theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = 1`
    `\<forall>k. _ \<longrightarrow> \<lfloor>r k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>r_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat>)`
    `\<lfloor>m_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>m_last\<rfloor>\<^sub>\<nat>`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0 mod_pos_pos_trivial fun_upd_comp del: num_of_lint_sum)

why3_end

end
