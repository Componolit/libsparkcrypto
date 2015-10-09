theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_14
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_14.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x_last - x_first + 1"
  from
    `l = x_last - x_first`
    `\<forall>k. \<lfloor>y__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>y__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>y__first\<rfloor>\<^sub>\<int> \<le> y_first`
    `y_first + (x_last - x_first) \<le> \<lfloor>y__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int \<circ> y) y_first ?l =
    num_of_big_int (word32_to_int \<circ> result1) 0 ?l"
    by (simp add: num_of_lint_ext)
  with
    `l = x_last - x_first`
    `(num_of_big_int' (Array lsc__bignum__mont_exp__a _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
    `result1 = slide lsc__bignum__mont_exp__a _ _`
  show ?thesis by (simp add: mk_bounds_eqs integer_in_range_def slide_eq)
qed

why3_end

end
