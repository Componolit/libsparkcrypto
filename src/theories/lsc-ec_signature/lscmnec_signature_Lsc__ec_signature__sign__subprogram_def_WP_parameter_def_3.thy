theory lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    `sign1_first < sign1_last`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by (simp add: one_def singleton0_def word32_to_int_def fun_upd_comp num_of_lint_all0)

why3_end

end
