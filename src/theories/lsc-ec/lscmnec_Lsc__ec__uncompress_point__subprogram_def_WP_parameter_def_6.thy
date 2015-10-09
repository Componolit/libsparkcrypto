theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
  using
    `x_first < x_last`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by (simp add: one_def singleton0_def word32_to_int_def num_of_lint_all0 fun_upd_comp)

why3_end

end
