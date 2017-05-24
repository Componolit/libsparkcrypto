theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_23
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_23.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x1_last - x1_first + 1"
  from
    `\<lfloor>y3__first\<rfloor>\<^sub>\<int> \<le> y3_first`
    `y3_first + (x1_last - x1_first) \<le> \<lfloor>y3__last\<rfloor>\<^sub>\<int>`
    `\<forall>k. \<lfloor>y3__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>y3__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
  have "num_of_big_int (word32_to_int \<circ> y31) y3_first ?l =
    num_of_big_int (word32_to_int \<circ> elts y1) y1_first ?l"
    by (simp add: num_of_lint_ext sign_simps)
  with `(num_of_big_int' y1 _ _ < num_of_big_int' m _ _) = _`
  show ?thesis by (simp add: map__content_def)
qed

why3_end

end
