theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_15
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_15.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "\<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat> + 1"
  from
    `l = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `\<forall>k. \<lfloor>y_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>y_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>y_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>y_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>y_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>) \<le> \<lfloor>y_last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> y) \<lfloor>y_first1\<rfloor>\<^sub>\<nat> ?l =
    num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_exp__a) 0 ?l"
    by (simp add: num_of_lint_ext mk_bounds_eqs integer_in_range_def slide_eq)
  with
    `l = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__bignum__mont_exp__a _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  show ?thesis by simp
qed

why3_end

end
