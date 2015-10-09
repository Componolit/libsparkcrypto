theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_73
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_73.xml"

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
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux1 _) _ _ = _) = _`
    `l = a_last - a_first`
  have "num_of_big_int (word32_to_int o a) a_first ?L =
    num_of_big_int (word32_to_int \<circ> elts x) x_first ?L ^
      nat (num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1) div
        2 ^ nat (uint i2 - s1 + 1)) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: power_mult_distrib mult.assoc base_eq)
  with Base_inv `(math_int_of_int s1 \<le> math_int_from_word i2 + _) = _`
    `BV64.ult i2 (of_int s1)` `0 \<le> s1` `s1 \<le> n_last ()`
  show ?thesis by (simp add: BV64.ult_def word_of_int uint_word_of_int
    mod_pos_pos_trivial n_last_def)
qed

why3_end

end
