theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_64
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_64.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1)"
  let ?x = "num_of_big_int (word32_to_int \<circ> elts x) x_first ?L"
  let ?R = "Base ^ nat ?L"

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
    num_of_big_int (word32_to_int o a2) a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  also from
    `(num_of_big_int' (Array a2 _) _ _ = _) = _`
    `(math_int_from_word w1 = _) = _`
    `s3 + 1 = r214b`
  have "num_of_big_int (word32_to_int o a2) a_first ?L =
    num_of_big_int (word32_to_int \<circ> aux32) aux3_first ?L *
    num_of_big_int (word32_to_int \<circ> aux4)
      (aux4_first + ?e div 2 ^ nat (uint i1 - (r214b - 1)) mod
       2 ^ nat r214b div 2 * ?L) ?L * minv ?m Base ^ nat ?L mod ?m"
    by (simp add: ediv_def base_eq BV32.facts.to_uint_lsr [of _ 1, simplified])
  also note `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    [simplified base_eq, simplified]
  also {
    have "?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b < 2 ^ nat r214b"
      by simp
    also from `s3 + 1 \<le> k + 1` `s3 + 1 = r214b`
    have "(2::int) ^ nat r214b \<le> 2 ^ nat (k + 1)"
      by simp
    with `natural_in_range k`
    have "(2::int) ^ nat r214b \<le> 2 * 2 ^ nat k"
      by (simp add: nat_add_distrib natural_in_range_def)
    finally have "?e div 2 ^ nat (uint i1 - (r214b - 1)) mod
      2 ^ nat r214b div 2 < 2 ^ nat k"
      by simp
    with
      `\<forall>n. 0 \<le> n \<and> n \<le> 2 ^ nat k - 1 \<longrightarrow> (num_of_big_int' (Array aux4 _) _ _ = _) = _`
    have "num_of_big_int (word32_to_int o aux4)
      (aux4_first + ?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b div 2 * ?L) ?L =
      ?x ^ nat (2 * (?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b div 2) + 1) *
      ?R mod ?m"
      by (simp add: pos_imp_zdiv_nonneg_iff base_eq)
  } also from
    `w mod of_int 2 = of_int 1`
    `(math_int_from_word w1 = _) = _`
    [simplified `s3 + 1 = r214b` `mk_t__ref w1 = mk_t__ref w` [simplified]]
  have "2 * (?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b div 2) + 1 =
    2 * (?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b div 2) +
    ?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b mod 2"
    by (simp add: num_of_lint_lower word32_to_int_lower
      word_uint_eq_iff uint_mod)
  also have "\<dots> = ?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b"
    by simp
  also from `0 \<le> s3 + 1` `s3 + 1 = r214b` `(math_int_of_int (s3 + 1) \<le> math_int_from_word i1 + _) = _`
  have "?e div 2 ^ nat (uint i1 + 1) =
    ?e div 2 ^ nat (uint i1 - (r214b - 1)) div 2 ^ nat r214b"
    by (simp add: zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric])
  also have
    "?x ^ nat (?e div 2 ^ nat (uint i1 - (r214b - 1)) div 2 ^ nat r214b * 2 ^ nat r214b) * ?R mod ?m *
     (?x ^ nat (?e div 2 ^ nat (uint i1 - (r214b - 1)) mod 2 ^ nat r214b) * ?R mod ?m) *
     minv ?m Base ^ nat ?L mod ?m =
     ?x ^ nat (?e div 2 ^ nat (uint i1 - (r214b - 1))) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      pos_imp_zdiv_nonneg_iff num_of_lint_lower
      mod_div_equality word32_to_int_lower)
  finally show ?thesis using `s3 + 1 = r214b`
    by (simp add: num_of_lint_lower word32_to_int_lower sign_simps base_eq o_def)
qed

why3_end

end
