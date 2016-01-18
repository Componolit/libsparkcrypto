theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_10
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_10.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  let ?r = "num_of_big_int (word32_to_int \<circ> elts r) r_first ?L"
  let ?R = "Base ^ nat ?L"
  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow> aux1 k = of_int 0`
    `a_first < a_last`
  have one: "num_of_big_int ((word32_to_int \<circ> aux1)(aux1_first := 1))
    aux1_first ?L = 1"
    by (simp add: num_of_lint_all0 word32_to_int_def)

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp add: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv]
      del: num_of_lint_sum)

  from `(num_of_big_int' r _ _ = _) = _`
    [unfolded base_eq, simplified math_int_conv math_int_of_int_inv]
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals] base_eq)
      (simp add: power_mult_distrib mult.assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  with
    `(num_of_big_int' (Array aux3 _) _ _ = _) = _`
    `o1 = of_int 1` one
  show ?thesis
    by (simp add: base_eq fun_upd_comp word32_to_int_def)
qed

why3_end

end
