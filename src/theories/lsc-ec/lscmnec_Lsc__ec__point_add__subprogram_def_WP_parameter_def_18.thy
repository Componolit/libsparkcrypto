theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_18
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_18.xml"

why3_vc WP_parameter_def
  using
    `x3 = x31` `l = o1`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `\<forall>k. \<lfloor>x3_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>x3_first1\<rfloor>\<^sub>\<nat> + \<lfloor>l\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>x31 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0)

why3_end

end
