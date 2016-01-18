theory lscmnbignum_Lsc__bignum__add_inplace__subprogram_def_WP_parameter_def_2
imports "../Add"
begin

why3_open "lscmnbignum_Lsc__bignum__add_inplace__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `a_first \<le> o1`
  have "num_of_big_int (word32_to_int o a) a_first (o1 + 1 - a_first) +
    int_of_math_int (num_of_big_int' b b_first (o1 + 1 - a_first)) =
    num_of_big_int (word32_to_int o a) a_first (o1 - a_first) +
    int_of_math_int (num_of_big_int' b b_first (o1 - a_first)) +
    (Base ^ nat (o1 - a_first) * \<lfloor>a o1\<rfloor>\<^sub>s +
     Base ^ nat (o1 - a_first) * \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s)"
    by (simp add: diff_add_eq [symmetric])
  moreover from `\<forall>k. o1 \<le> k \<and> k \<le> a_last \<longrightarrow> a1 k = a k`
    `o1 \<le> a_last`
  have "\<lfloor>a o1\<rfloor>\<^sub>s = \<lfloor>a1 o1\<rfloor>\<^sub>s" by simp
  ultimately show ?thesis using
    `o2 = _`
    `(num_of_big_int' (Array a _) _ _ + num_of_big_int' b _ _ = _) = _`
    `(math_int_from_word (word_of_boolean carry1) = num_of_bool carry1) = _`
    `a_first \<le> o1`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib
      add_carry div_mod_eq ring_distribs base_eq fun_upd_comp
      uint_lt [where 'a=32, simplified]
      word32_to_int_def uint_word_ariths BV32.ult_def
      word_uint_eq_iff
        [where 'a=32,
         of "a1 o1 + elts b (b_first + (o1 - a_first)) + word_of_boolean carry1"
           "a1 o1"])
qed

why3_end

end
