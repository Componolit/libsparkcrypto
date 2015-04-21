theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_8
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "\<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat> + 1"
  from
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `\<forall>k. \<lfloor>y3_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>y3_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>y3_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>y3_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>y3_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>) \<le> \<lfloor>y3_last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> y33) \<lfloor>y3_first1\<rfloor>\<^sub>\<nat> ?l =
    num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__y2) 0 ?l"
    by (simp add: num_of_lint_ext mk_bounds_eqs integer_in_range_def slide_eq)
  with
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__ec__point_double__y2 _) _ _ < num_of_big_int' m _ _) = _`
  show ?thesis by simp
qed

why3_end

end
