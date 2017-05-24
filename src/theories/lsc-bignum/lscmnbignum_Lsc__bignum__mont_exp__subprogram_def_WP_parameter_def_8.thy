theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_8
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  let ?x = "num_of_big_int (word32_to_int \<circ> elts x) x_first ?L"
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) (o2 + 1) (e_last - o2)"
  let ?R = "Base ^ nat ?L"
  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `a_first < a_last` `(_ < num_of_big_int' m _ _) = _` [simplified]
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `(num_of_big_int' (Array aux33 _) _ _ = _) = _`
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux2 _) aux2_first ?L = _) = _`
  have "num_of_big_int (word32_to_int o aux33) aux3_first ?L =
    ?x ^ nat ((?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2) *
    ?x * ?R mod ?m"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult.commute] base_eq)
      (simp add: mont_mult_eq [OF Base_inv] power_mult power2_eq_square word32_to_int_def)
  also have "\<dots> =
    ?x ^ nat ((?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1) *
    ?R mod ?m"
    by (simp add: nat_add_distrib num_of_lint_lower word32_to_int_lower
      pos_imp_zdiv_nonneg_iff mult.commute)
  also from `0 \<le> j` `j \<le> 31`
  have "(?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1 =
    ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 + 1"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult.commute [of _ 2]])
  also from `(if (if elts e o2 AND (of_int 1 << unat (of_int j)) = of_int 0 then _ else _) \<noteq> _ then _ else _) = _`
    power_increasing [OF nat_mono [OF `j \<le> 31`], of "2::int"] `0 \<le> j` `j \<le> 31`
  have "\<dots> = ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 +
    \<lfloor>elts e o2\<rfloor>\<^sub>s div 2 ^ nat j mod 2"
    by (simp add: AND_div_mod word_uint_eq_iff uint_and uint_pow
      mod_pos_pos_trivial word32_to_int_def unat_def uint_word_of_int word_of_int)
  finally show ?thesis
    by (simp add: add.commute base_eq o_def word32_to_int_def)
qed

why3_end

end
