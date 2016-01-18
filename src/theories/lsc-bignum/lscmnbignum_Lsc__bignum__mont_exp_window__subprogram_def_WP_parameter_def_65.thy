theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_65
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_65.xml"

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
    `natural_in_range e_first`
    `natural_in_range e_last`
    `BV64.ult i1 ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `e_first \<le> e_last`
  have i: "uint i1 < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial emod_def BV64.ult_def uint_word_ariths
      word_of_int uint_word_of_int natural_in_range_def)

  from
    `\<forall>k. \<lfloor>aux3__first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux3__last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>aux3__first\<rfloor>\<^sub>\<int> \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> \<lfloor>aux3__last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int o aux32) aux3_first ?L =
    num_of_big_int (word32_to_int o a2) a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  with
    `(num_of_big_int' (Array a2 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
  have "num_of_big_int (word32_to_int o aux32) aux3_first ?L =
    ?x ^ nat ((?e div 2 ^ nat (uint i1) div 2) * 2) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      num_of_lint_lower pos_imp_zdiv_nonneg_iff base_eq word32_to_int_lower)
      (simp add: nat_add_distrib zdiv_zmult2_eq [symmetric] mult_ac word64_to_int_lower)
  also have "(?e div 2 ^ nat (uint i1) div 2) * 2 =
    ?e div 2 ^ nat (uint i1) - ?e div 2 ^ nat (uint i1) mod 2"
    by (simp add: mod_div_equality')
  also from i
    `bit_set e e_first i1 \<noteq> True`
    `(bit_set e e_first i1 = True) = _`
  have "?e AND 2 ^ nat (uint i1) = 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      uint_lt [where 'a=32, simplified]
      word_uint_eq_iff uint_and uint_pow uint_div uint_mod
      power_strict_increasing [of _ 32 2, simplified] mod_pos_pos_trivial
      word32_to_int_def
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (uint i1) mod 2 = 0"
    by (simp add: AND_div_mod)
  finally show ?thesis
    by (simp add: base_eq o_def)
qed

why3_end

end
