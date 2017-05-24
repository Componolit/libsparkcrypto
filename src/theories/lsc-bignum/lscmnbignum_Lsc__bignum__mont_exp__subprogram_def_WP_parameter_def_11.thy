theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_11
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  let ?x = "num_of_big_int (word32_to_int \<circ> elts x) x_first ?L"
  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _` [simplified]
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
    `(num_of_big_int' (Array (aux1(aux1_first := o1)) _) _ _ = _) = _`
    `e_first \<le> e_last`
  have "num_of_big_int (word32_to_int o a) a_first ?L =
    ?x ^ nat (num_of_big_int (word32_to_int \<circ> elts e) e_first (1 + (e_last - e_first))) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: map__content_def)
      (simp only: power_mult_distrib [symmetric] mult.assoc base_eq word32_to_int_def,
        simp add: add.commute mult.commute)
  with Base_inv show ?thesis by (simp add: add.commute map__content_def)
qed

why3_end

end
