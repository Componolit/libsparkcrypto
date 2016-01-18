theory lscmnbignum_Lsc__bignum__add_mult_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__add_mult_mult__subprogram_def_WP_parameter_def_2.xml"

notation math_int_from_word ("\<lfloor>_\<rfloor>\<^sub>m")

why3_vc WP_parameter_def
proof -
  note inv = `(num_of_big_int' (Array a _) _ _ + num_of_big_int' b _ _ * \<lfloor>x\<rfloor>\<^sub>m +
    num_of_big_int' c _ _ * \<lfloor>y\<rfloor>\<^sub>m + \<lfloor>carry1\<rfloor>\<^sub>m + _ * \<lfloor>carry2\<rfloor>\<^sub>m = _) = _`
    [simplified base_eq, simplified]
  note single =
    `(\<lfloor>a1 _\<rfloor>\<^sub>m + \<lfloor>elts b _\<rfloor>\<^sub>m * \<lfloor>x\<rfloor>\<^sub>m + \<lfloor>elts c _\<rfloor>\<^sub>m * \<lfloor>y\<rfloor>\<^sub>m +
      \<lfloor>carry11\<rfloor>\<^sub>m + _ * \<lfloor>carry21\<rfloor>\<^sub>m = _) = _`
    [simplified, simplified base_eq]
  from `a_first \<le> o1` `o1 \<le> a_last`
    `\<forall>k. o1 \<le> k \<and> k \<le> a_last + 1 \<longrightarrow> a1 k = a k`
  have "num_of_big_int (word32_to_int o a) (a_first + 1) (o1 + 1 - a_first) +
    num_of_big_int (word32_to_int \<circ> elts b) b_first (o1 + 1 - a_first) * \<lfloor>x\<rfloor>\<^sub>s +
    num_of_big_int (word32_to_int \<circ> elts c) c_first (o1 + 1 - a_first) * \<lfloor>y\<rfloor>\<^sub>s +
    \<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s =
    num_of_big_int (word32_to_int o a) (a_first + 1) (o1 - a_first) +
    num_of_big_int (word32_to_int \<circ> elts b) b_first (o1 - a_first) * \<lfloor>x\<rfloor>\<^sub>s +
    num_of_big_int (word32_to_int \<circ> elts c) c_first (o1 - a_first) * \<lfloor>y\<rfloor>\<^sub>s +
    \<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s +
    Base ^ nat (o1 - a_first) *
      (\<lfloor>a1 (o1 + 1)\<rfloor>\<^sub>s +
       \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>x\<rfloor>\<^sub>s +
       \<lfloor>elts c (c_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s)"
    by (simp add: diff_add_eq [symmetric] ring_distribs)
      (simp add: add.commute)
  also note inv [simplified, folded word32_to_int_def]
  also have "num_of_big_int (word32_to_int o a1) a_first (o1 - a_first) +
    Base ^ nat (o1 - a_first) * (\<lfloor>carry11\<rfloor>\<^sub>s + Base * \<lfloor>carry21\<rfloor>\<^sub>s) +
    Base ^ nat (o1 - a_first) *
      (\<lfloor>a1 (o1 + 1)\<rfloor>\<^sub>s +
       \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>x\<rfloor>\<^sub>s +
       \<lfloor>elts c (c_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s) =
    num_of_big_int (word32_to_int o a1) a_first (o1 - a_first) +
    Base ^ nat (o1 - a_first) *
      (\<lfloor>a1 (o1 + 1)\<rfloor>\<^sub>s +
       \<lfloor>elts b (b_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>x\<rfloor>\<^sub>s +
       \<lfloor>elts c (c_first + (o1 - a_first))\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s +
       \<lfloor>carry11\<rfloor>\<^sub>s + Base * \<lfloor>carry21\<rfloor>\<^sub>s)"
    by (simp add: ring_distribs)
  also note single [simplified, folded word32_to_int_def]
  finally show ?thesis using `a_first \<le> o1`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib ring_distribs fun_upd_comp base_eq)
      (simp add: o_def word32_to_int_def)
qed

why3_end

end
