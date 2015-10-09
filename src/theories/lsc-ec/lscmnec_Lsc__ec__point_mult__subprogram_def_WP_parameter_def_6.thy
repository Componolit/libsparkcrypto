theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x1_last - x1_first + 1"
  from
    `\<forall>k. \<lfloor>z2__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>z2__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>z2__first\<rfloor>\<^sub>\<int> \<le> z2_first`
    `z2_first + (x1_last - x1_first) \<le> \<lfloor>z2__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> z23) z2_first ?l =
    num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__z2) 0 ?l"
    by (simp add: num_of_lint_ext mk_bounds_eqs integer_in_range_def slide_eq)
  with
    `(num_of_big_int' (Array lsc__ec__point_double__z2 _) _ _ < num_of_big_int' m _ _) = _`
  show ?thesis by simp
qed

why3_end

end
