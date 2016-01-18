theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_48
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_48.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp add: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv]
      del: num_of_lint_sum)

  from
    `\<forall>k. \<lfloor>aux3__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux3__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>aux3__first\<rfloor>\<^sub>\<int> \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> \<lfloor>aux3__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int o aux33) aux3_first ?L =
    num_of_big_int (word32_to_int o a8) a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  moreover from `1 \<le> h8`
  have "nat h8 = nat (h8 - 1) + 1"
    by simp
  ultimately show ?thesis
    using
      `(num_of_big_int' (Array a8 _) _ _ = _) = _`
      `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    by (simp add: mont_mult_eq [OF Base_inv] power_add base_eq)
      (simp add: mult_ac nat_mult_distrib power_mult power2_eq_square
         power_mult_distrib)
qed

why3_end

end
