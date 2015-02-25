theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = 0`
    `\<forall>k. \<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>a k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `(1 < num_of_big_int' m _ _) = True`
  by (simp_all add: num_of_lint_all0)

why3_end

end
