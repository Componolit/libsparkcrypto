theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_53
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_53.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `\<forall>k. \<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int o aux33) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L =
    num_of_big_int (word32_to_int o a8) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  moreover from `1 \<le> h6`
  have "nat h6 = nat (h6 - 1) + 1"
    by simp
  ultimately show ?thesis
    using
      `(num_of_big_int' (Array a8 _) _ _ = _) = _`
      `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
      `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    by (simp add: mont_mult_eq [OF Base_inv] power_add base_eq)
      (simp add: mult_ac nat_mult_distrib power_mult power2_eq_square
         power_mult_distrib)
qed

why3_end

end
