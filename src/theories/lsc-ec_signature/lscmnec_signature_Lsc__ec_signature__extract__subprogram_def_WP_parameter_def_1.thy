theory lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `x_first < x_last`
    `(math_int_from_word (of_int 1) < num_of_big_int' n _ _) = _`
  by (simp add: one_def singleton0_def fun_upd_comp word32_to_int_def num_of_lint_all0)

why3_end

end
