theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_13
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_13.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "x_last - x_first + 1"
  from
    `(num_of_big_int' (Array lsc__bignum__mont_exp__a _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  have "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_exp__a) 0 ?l <
    num_of_big_int (word32_to_int \<circ> elts m) m_first ?l"
    by simp
  moreover have "0 \<le> num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_exp__a) 0 ?l"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "num_of_big_int (word32_to_int \<circ> y) y_first ?l < Base ^ nat ?l"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  ultimately show ?thesis using
    `(_ = num_of_big_int' (Array y _) _ _ - _) = _`
    `is_zero (Array _ _) _ _ \<noteq> True`
    `(is_zero (Array _ _) _ _ = True) = _`
    by (cases carry1) (simp_all add: mk_bounds_eqs integer_in_range_def slide_eq base_eq)
qed

why3_end

end
