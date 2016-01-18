theory lscmnbignum_Lsc__bignum__sub_inplace__subprogram_def_WP_parameter_def_3
imports "../Sub"
begin

why3_open "lscmnbignum_Lsc__bignum__sub_inplace__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `_ = (if BV32.ult (a1 o1) (elts b (b_first + (o1 - a_first))) then _ else _)`
  have eq: "num_of_bool True = num_of_bool
    (\<lfloor>a1 o1\<rfloor>\<^sub>s < \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s \<or>
     \<lfloor>a1 o1\<rfloor>\<^sub>s = \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s \<and> carry1)"
    by (simp add: BV32.ult_def word32_to_int_def)
  from `a_first \<le> o1`
  have "num_of_big_int (word32_to_int o a) a_first (o1 + 1 - a_first) -
    int_of_math_int (num_of_big_int' b b_first (o1 + 1 - a_first)) =
    num_of_big_int (word32_to_int o a) a_first (o1 - a_first) -
    int_of_math_int (num_of_big_int' b b_first (o1 - a_first)) +
    (Base ^ nat (o1 - a_first) * \<lfloor>a o1\<rfloor>\<^sub>s -
     Base ^ nat (o1 - a_first) * \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s)"
    by (simp add: diff_add_eq [symmetric])
  moreover from `\<forall>k. o1 \<le> k \<and> k \<le> a_last \<longrightarrow> a1 k = a k`
    `o1 \<le> a_last`
  have "a o1 = a1 o1" by simp
  ultimately show ?thesis using
    `(num_of_big_int' (Array a _) _ _ - num_of_big_int' b _ _ = _) = _`
    `a_first \<le> o1`
    `o2 = _`
    `(math_int_from_word (word_of_boolean carry1) = num_of_bool carry1) = _`
    by (simp (no_asm_simp) only: eq)
      (simp add: diff_add_eq [symmetric] nat_add_distrib
       sub_carry [of _ Base] div_mod_eq ring_distribs base_eq
       fun_upd_comp uint_lt [where 'a=32, simplified]
       word32_to_int_def uint_word_ariths del: uint_inject)
qed

why3_end

end
