theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3.xml"

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

  from `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
    result k = of_int 0`
    `a_first < a_last` `o1 = _`
  show one: ?C1 by (simp add: num_of_lint_all0 fun_upd_comp word32_to_int_def)

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _` [simplified]
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from `(num_of_big_int' r  _ _ = _) = _`
    [unfolded base_eq, simplified math_int_conv math_int_of_int_inv]
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals])
      (simp add: power_mult_distrib mult.assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  from `(num_of_big_int' (Array aux2 _) _ _ = _) = _`
  have "num_of_big_int (word32_to_int o aux2) aux2_first ?L =
    ?x * (?r * minv ?m Base ^ nat ?L mod ?m) mod ?m"
    by (simp add: mult.assoc base_eq)
  with R show ?C2 by (simp add: base_eq)

  from `(num_of_big_int' (Array aux3 _) _ _ = _) = _` one R
  show ?C3 by (simp add: base_eq)
qed

why3_end

end
