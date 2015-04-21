theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>x_first\<rfloor>\<^sub>\<nat> < \<lfloor>x_last\<rfloor>\<^sub>\<nat>`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: one_def singleton0_def word32_coerce emod_def num_of_lint_all0 fun_upd_comp)

why3_end

end
