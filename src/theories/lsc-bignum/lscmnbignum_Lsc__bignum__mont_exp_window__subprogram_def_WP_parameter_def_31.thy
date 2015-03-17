theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_31
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_31.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?x = "num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L"
  let ?r = "num_of_big_int' r \<lfloor>r_first\<rfloor>\<^sub>\<nat> ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  note copy =
    `\<forall>k. \<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`

  note n = `0 \<le> n` `n \<le> h`

  have "num_of_big_int (word32_to_int o aux42) (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L) ?L =
    ?x ^ nat (2 * n + 1) * ?R mod ?m"
  proof (cases "n = h")
    case False
    have "num_of_big_int (word32_to_int o aux42) (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L) ?L =
      num_of_big_int (word32_to_int o aux41) (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L) ?L"
    proof (intro num_of_lint_ext ballI, unfold o_def)
      fix j
      assume j: "j \<in> {\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L..<\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L + ?L}"
      from n `h \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "n * ?L \<le> (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1) * ?L"
        by simp
      with `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "n * ?L + ?L \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * ?L"
        by (simp add: sign_simps)
      with j `\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * ?L - 1) \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>`
      have "j \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>" by simp
      moreover from n `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> \<le> \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L"
        by (simp add: mult_nonneg_nonneg)
      with j `\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat>`
      have "\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> j"
        by simp
      moreover from n False have "n \<le> h - 1" by simp
      with `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` have "n * ?L + ?L \<le> (h - 1) * ?L + ?L"
        by simp
      with j have "j < \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + h * ?L"
        by (simp add: left_diff_distrib)
      ultimately have "\<lfloor>aux42 j\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>aux41 j\<rfloor>\<^bsub>w32\<^esub>"
        using copy `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
        by simp
      then show "\<lfloor>aux42 j\<rfloor>\<^bsub>w32\<^esub> =
        \<lfloor>aux41 (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L + (j - (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L)))\<rfloor>\<^bsub>w32\<^esub>"
        by simp
    qed
    with n False `\<forall>n. 0 \<le> n \<and> n \<le> h - 1 \<longrightarrow>
       (num_of_big_int' (Array aux41 _) _ _ = _) = _`
      `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    show ?thesis by (simp add: base_eq)
  next
    case True
    have "num_of_big_int (word32_to_int o aux42) (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L) ?L =
      num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L"
    proof (intro num_of_lint_ext ballI, unfold o_def)
      fix j
      assume j: "j \<in> {\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L..<\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * ?L + ?L}"
      from n `h \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "n * ?L \<le> (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1) * ?L"
        by simp
      with `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "n * ?L + ?L \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * ?L"
        by (simp add: sign_simps)
      with j `\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * ?L - 1) \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>`
      have "j \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>" by simp
      moreover from n `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
      have "\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + n * ?L"
        by (simp add: mult_nonneg_nonneg)
      with j `\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat>`
      have "\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> j"
        by simp
      ultimately show "\<lfloor>aux42 j\<rfloor>\<^bsub>w32\<^esub> =
        \<lfloor>a (\<lfloor>a_first1\<rfloor>\<^sub>\<nat> + (j - (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + n * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1))))\<rfloor>\<^bsub>w32\<^esub>"
        using copy True j `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
        by (simp add: sign_simps)
    qed
    with True
      `(num_of_big_int' (Array a _) _ _ = _) = _`
      `(num_of_big_int' (Array aux2 _) _ _ = _) = _`
      `\<forall>n. 0 \<le> n \<and> n \<le> h - 1 \<longrightarrow>
         (num_of_big_int' (Array aux41 _) _ _ = _) = _`
      `1 \<le> h`
      `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    show ?thesis
      by (simp add: mont_mult_eq [OF Base_inv] base_eq)
        (simp add: mult_ac comm_semiring_1_class.normalizing_semiring_rules(27)
           Suc_nat_eq_nat_zadd1 add_ac mult_ac)
  qed
  with `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  show ?thesis by (simp add: base_eq)
qed

why3_end

end
