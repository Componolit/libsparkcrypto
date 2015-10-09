theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_26
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_26.xml"

why3_vc WP_parameter_def
  using
    `z3 = z31` `l = x1_last - x1_first`
    `\<forall>k. z3_first \<le> k \<and> k \<le> z3_first + l \<longrightarrow> z31 k = of_int 0`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by (simp add: num_of_lint_all0 word32_to_int_def)

why3_end

end
