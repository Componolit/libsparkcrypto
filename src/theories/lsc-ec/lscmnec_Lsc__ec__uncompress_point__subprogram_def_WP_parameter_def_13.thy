theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_13
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_13.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "\<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat> + 1"
  from
    `l = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__bignum__mont_exp__a _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  have "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_exp__a) 0 ?l <
    num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?l"
    by simp
  moreover have "0 \<le> num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_exp__a) 0 ?l"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "num_of_big_int (word32_to_int \<circ> y1) \<lfloor>y_first1\<rfloor>\<^sub>\<nat> ?l < Base ^ nat ?l"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  ultimately show ?thesis using
    `y = y1` `l = o1`
    `(_ = num_of_big_int' (Array y1 _) _ _ - _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `is_zero (Array (slide lsc__bignum__mont_exp__a _ _) _) _ _ \<noteq> True`
    `(is_zero (Array (slide lsc__bignum__mont_exp__a _ _) _) _ _ = True) = _`
    by (cases carry) (simp_all add: mk_bounds_eqs integer_in_range_def slide_eq base_eq)
qed

why3_end

end
