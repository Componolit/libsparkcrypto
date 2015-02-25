theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = 1`
    `\<forall>k. \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) \<longrightarrow>
       \<lfloor>aux1 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0 fun_upd_comp)

why3_end

end
