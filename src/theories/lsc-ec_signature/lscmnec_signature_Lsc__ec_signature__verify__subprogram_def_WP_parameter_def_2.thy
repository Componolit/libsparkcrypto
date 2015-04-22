theory lscmnec_signature_Lsc__ec_signature__verify__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__verify__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>sign1_last\<rfloor>\<^sub>\<nat> - \<lfloor>sign1_first\<rfloor>\<^sub>\<nat>`
    `\<lfloor>sign1_first\<rfloor>\<^sub>\<nat> < \<lfloor>sign1_last\<rfloor>\<^sub>\<nat>`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: one_def singleton0_def word32_coerce emod_def fun_upd_comp num_of_lint_all0)

why3_end

end
