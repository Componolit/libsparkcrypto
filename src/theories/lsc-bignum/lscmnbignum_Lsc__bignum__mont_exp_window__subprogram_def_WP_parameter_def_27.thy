theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_27
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_27.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  let ?x = "num_of_big_int (word32_to_int \<circ> elts x) x_first ?L"
  let ?r = "num_of_big_int (word32_to_int \<circ> elts r) r_first ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp add: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv]
      del: num_of_lint_sum)

  note copy =
    `\<forall>k. \<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`

  note n = `0 \<le> n` `n \<le> h1`

  have "num_of_big_int (word32_to_int o aux42) (aux4_first + n * ?L) ?L =
    ?x ^ nat (2 * n + 1) * ?R mod ?m"
  proof (cases "n = h1")
    case False
    have "num_of_big_int (word32_to_int o aux42) (aux4_first + n * ?L) ?L =
      num_of_big_int (word32_to_int o aux41) (aux4_first + n * ?L) ?L"
    proof (intro num_of_lint_ext ballI, unfold o_def)
      fix j
      assume j: "j \<in> {aux4_first + n * ?L..<aux4_first + n * ?L + ?L}"
      from n `h1 \<le> 2 ^ nat k - 1` `a_first < a_last`
      have "n * ?L \<le> (2 ^ nat k - 1) * ?L"
        by simp
      with `a_first < a_last`
      have "n * ?L + ?L \<le> 2 ^ nat k * ?L"
        by (simp add: sign_simps)
      with j `aux4_first + (2 ^ nat k * ?L - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
      have "j \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>" by simp
      moreover from n `a_first < a_last`
      have "aux4_first \<le> aux4_first + n * ?L"
        by simp
      with j `\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> aux4_first`
      have "\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> j"
        by simp
      moreover from n False have "n \<le> h1 - 1" by simp
      with `a_first < a_last` have "n * ?L + ?L \<le> (h1 - 1) * ?L + ?L"
        by simp
      with j have "j < aux4_first + h1 * ?L"
        by (simp add: left_diff_distrib)
      ultimately have "\<lfloor>aux42 j\<rfloor>\<^sub>s = \<lfloor>aux41 j\<rfloor>\<^sub>s"
        using copy
        by simp
      then show "\<lfloor>aux42 j\<rfloor>\<^sub>s =
        \<lfloor>aux41 (aux4_first + n * ?L + (j - (aux4_first + n * ?L)))\<rfloor>\<^sub>s"
        by simp
    qed
    with n False `\<forall>n. 0 \<le> n \<and> n \<le> h1 - 1 \<longrightarrow>
       (num_of_big_int' (Array aux41 _) _ _ = _) = _`
    show ?thesis by (simp add: base_eq)
  next
    case True
    have "num_of_big_int (word32_to_int o aux42) (aux4_first + n * ?L) ?L =
      num_of_big_int (word32_to_int o a) a_first ?L"
    proof (intro num_of_lint_ext ballI, unfold o_def)
      fix j
      assume j: "j \<in> {aux4_first + n * ?L..<aux4_first + n * ?L + ?L}"
      from n `h1 \<le> 2 ^ nat k - 1` `a_first < a_last`
      have "n * ?L \<le> (2 ^ nat k - 1) * ?L"
        by simp
      with `a_first < a_last`
      have "n * ?L + ?L \<le> 2 ^ nat k * ?L"
        by (simp add: sign_simps)
      with j `aux4_first + (2 ^ nat k * ?L - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
      have "j \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>" by simp
      moreover from n `a_first < a_last`
      have "a_first \<le> a_first + n * ?L"
        by simp
      with j `\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> aux4_first`
      have "\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> j"
        by simp
      ultimately show "\<lfloor>aux42 j\<rfloor>\<^sub>s =
        \<lfloor>a (a_first + (j - (aux4_first + n * (a_last - a_first + 1))))\<rfloor>\<^sub>s"
        using copy True j
        by (simp add: sign_simps)
    qed
    with True
      `(num_of_big_int' (Array a _) _ _ = _) = _`
      `(num_of_big_int' (Array aux2 _) _ _ = _) = _`
      `\<forall>n. 0 \<le> n \<and> n \<le> h1 - 1 \<longrightarrow>
         (num_of_big_int' (Array aux41 _) _ _ = _) = _`
      `1 \<le> h1`
    show ?thesis
      by (simp add: mont_mult_eq [OF Base_inv] base_eq)
        (simp add: power_Suc [symmetric]
           Suc_nat_eq_nat_zadd1 add_ac mult_ac)
  qed
  then show ?thesis by (simp add: base_eq)
qed

why3_end

end
