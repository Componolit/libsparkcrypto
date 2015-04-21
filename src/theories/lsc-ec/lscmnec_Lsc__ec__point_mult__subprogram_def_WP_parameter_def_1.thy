theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `\<forall>k. \<lfloor>x2_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>x2_first1\<rfloor>\<^sub>\<nat> + \<lfloor>o1\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>x2 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0)

why3_end

end
