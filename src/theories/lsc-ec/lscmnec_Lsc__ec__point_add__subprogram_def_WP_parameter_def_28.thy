theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_28
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_28.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x1_last - x1_first + 1"
  from
    `\<forall>k. \<lfloor>z3__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>z3__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>z3__first\<rfloor>\<^sub>\<int> \<le> z3_first`
    `z3_first + (x1_last - x1_first) \<le> \<lfloor>z3__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> z31) z3_first ?l =
    num_of_big_int (word32_to_int \<circ> elts z2) z2_first ?l"
    by (simp add: num_of_lint_ext sign_simps)
  with `(num_of_big_int' z2 _ _ < num_of_big_int' m _ _) = _`
  show ?thesis by simp
qed

why3_end

end
