theory lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>sign1_last1\<rfloor>\<^sub>\<nat> - \<lfloor>sign1_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>sign1_first1\<rfloor>\<^sub>\<nat> < \<lfloor>sign1_last1\<rfloor>\<^sub>\<nat>`
    `(1 < num_of_big_int' n _ _) = _`
  by (simp add: one_def singleton0_def word32_coerce emod_def fun_upd_comp num_of_lint_all0)

why3_end

end
