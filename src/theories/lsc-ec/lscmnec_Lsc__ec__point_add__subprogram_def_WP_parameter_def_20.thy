theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_20
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_20.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x1_last - x1_first + 1"
  from
    `\<forall>k. \<lfloor>x3__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>x3__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>x3__first\<rfloor>\<^sub>\<int> \<le> x3_first`
    `x3_first + (x1_last - x1_first) \<le> \<lfloor>x3__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> x31) x3_first ?l =
    num_of_big_int (word32_to_int \<circ> elts x2) x2_first ?l"
    by (simp add: num_of_lint_ext sign_simps)
  with `(num_of_big_int' x2 _ _ < num_of_big_int' m _ _) = _`
  show ?thesis by (simp add: map__content_def)
qed

why3_end

end
