theory Mont_Exp
imports Bignum
begin

lemma mont_mult_eq:
  assumes "B * B_inv mod m = (1::int)"
  shows "(x * B ^ n) * (y * B ^ n) * B_inv ^ n mod m = x * y * B ^ n mod m"
proof -
  have "(x * B ^ n) * (y * B ^ n) * B_inv ^ n mod m =
    x * y * B ^ n * (B * B_inv mod m) ^ n mod m"
    by (simp add: power_mult_distrib mult_ac)
  with `B * B_inv mod m = 1` show ?thesis by simp
qed

spark_open "$VCG_DIR/lsc_/bignum/mont_exp" (lsc__bignum)

spark_vc procedure_mont_exp_3
  using
    `a_first < a_last`
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
    `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
       aux1__1 k = 0`
  by (simp add: num_of_lint_all0 sign_simps)

spark_vc procedure_mont_exp_4
  using
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
    `num_of_big_int r r_first (a_last - a_first + 1) =
     Base ^ nat (2 * (a_last - a_first + 1)) mod
     num_of_big_int m m_first (a_last - a_first + 1)`
  by (simp add: sign_simps)

spark_vc procedure_mont_exp_7
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  let ?r = "num_of_big_int r r_first ?L"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
    aux1__1 k = 0`
    `a_first < a_last`
  show one: ?C1 by (simp add: num_of_lint_all0)

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from `?r = _`
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals])
      (simp add: power_mult_distrib mult_assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  from `num_of_big_int aux2__3 _ _ = _`
  have "num_of_big_int aux2__3 aux2_first ?L =
    ?x * (?r * minv ?m Base ^ nat ?L mod ?m) mod ?m"
    by (simp add: mult_assoc)
  with R show ?C2 by simp

  from `num_of_big_int aux3__2 _ _ = _` one R
  show ?C3 by simp
qed

spark_vc procedure_mont_exp_9
proof -
  have e: "e_last - (loop__1__i - 1) = 1 + (e_last - loop__1__i)"
    by simp
  from `num_of_big_int aux3 _ _ = _` `loop__1__i \<le> e_last`
  show ?thesis
    by (simp add: e add_ac mult_ac)
qed

spark_vc procedure_mont_exp_12
proof -
  from `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
    `e_first \<le> loop__1__i` `loop__1__i \<le> e_last`
  have "0 \<le> e loop__1__i" "e loop__1__i < Base" by simp_all
  with `num_of_big_int aux3 _ _ = _`
  show ?thesis
    by (simp add: sdiv_pos_pos div_pos_pos_trivial)
qed

spark_vc procedure_mont_exp_16
  using `num_of_big_int aux2 _ _ = _`
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
  by (simp add: sign_simps)

spark_vc procedure_mont_exp_18
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  let ?e = "num_of_big_int e (loop__1__i + 1) (e_last - loop__1__i)"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `num_of_big_int aux3__5 _ _ = _`
    `num_of_big_int a__4 _ _ = _`
    `num_of_big_int aux3 _ _ = _`
    `num_of_big_int aux2 _ _ = _`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> e__index__subtype__1__last`
  have "num_of_big_int aux3__5 aux3_first ?L =
    ?x ^ nat ((?e * 2 ^ nat (31 - loop__2__j) +
      e loop__1__i div 2 ^ nat (loop__2__j + 1)) * 2) *
    ?x * ?R mod ?m"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult_commute])
      (simp add: mont_mult_eq [OF Base_inv] sdiv_pos_pos power_mult power2_eq_square)
  also from `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> e_last`
    `e_last \<le> e__index__subtype__1__last`
  have "\<dots> =
    ?x ^ nat ((?e * 2 ^ nat (31 - loop__2__j) +
      e loop__1__i div 2 ^ nat (loop__2__j + 1)) * 2 + 1) *
    ?R mod ?m"
    by (simp add: nat_add_distrib num_of_lint_lower mult_nonneg_nonneg
      pos_imp_zdiv_nonneg_iff mult_commute)
  also from `0 \<le> loop__2__j` `loop__2__j \<le> 31`
  have "(?e * 2 ^ nat (31 - loop__2__j) +
      e loop__1__i div 2 ^ nat (loop__2__j + 1)) * 2 + 1 =
    ?e * 2 ^ nat (31 - loop__2__j + 1) +
    e loop__1__i div 2 ^ nat loop__2__j div 2 * 2 + 1"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult_commute [of _ 2]])
  also from `e loop__1__i AND 2 ^ nat loop__2__j \<noteq> 0`
  have "\<dots> = ?e * 2 ^ nat (31 - loop__2__j + 1) +
    e loop__1__i div 2 ^ nat loop__2__j div 2 * 2 +
    e loop__1__i div 2 ^ nat loop__2__j mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> loop__1__i`
      `loop__1__i \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos add_commute)
qed

spark_vc procedure_mont_exp_19
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  let ?e = "num_of_big_int e (loop__1__i + 1) (e_last - loop__1__i)"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `\<forall>k. aux3__index__subtype__1__first \<le> k \<and> k \<le> aux3__index__subtype__1__last \<longrightarrow>
       (aux3_first \<le> k \<and> k \<le> aux3_first + a_last - a_first \<longrightarrow>
          aux3__6 k = a__4 (a_first + k - aux3_first)) \<and>
       (k < aux3_first \<or> aux3_first + a_last - a_first < k \<longrightarrow>
          aux3__6 k = aux3 k)`
    `aux3__index__subtype__1__first \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> aux3__index__subtype__1__last`
  have "num_of_big_int aux3__6 aux3_first (a_last - a_first + 1) =
    num_of_big_int a__4 a_first (a_last - a_first + 1)"
    by (simp add: num_of_lint_def)
  also from
    `num_of_big_int a__4 _ _ = _`
    `num_of_big_int aux3 _ _ = _`
    `num_of_big_int aux2 _ _ = _`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> e__index__subtype__1__last`
  have "\<dots> =
    ?x ^ nat ((?e * 2 ^ nat (31 - loop__2__j) +
      e loop__1__i div 2 ^ nat (loop__2__j + 1)) * 2) *
    ?R mod ?m"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult_commute])
      (simp add: mont_mult_eq [OF Base_inv] sdiv_pos_pos power_mult power2_eq_square)
  also from `0 \<le> loop__2__j` `loop__2__j \<le> 31`
  have "(?e * 2 ^ nat (31 - loop__2__j) +
      e loop__1__i div 2 ^ nat (loop__2__j + 1)) * 2 =
    ?e * 2 ^ nat (31 - loop__2__j + 1) +
    e loop__1__i div 2 ^ nat loop__2__j div 2 * 2"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult_commute [of _ 2]])
  also from `e loop__1__i AND 2 ^ nat loop__2__j = 0`
  have "\<dots> = ?e * 2 ^ nat (31 - loop__2__j + 1) +
    e loop__1__i div 2 ^ nat loop__2__j div 2 * 2 +
    e loop__1__i div 2 ^ nat loop__2__j mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> loop__1__i`
      `loop__1__i \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos add_commute)
qed

spark_vc procedure_mont_exp_25
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `num_of_big_int a__7 _ _ = _`
    `num_of_big_int aux3 _ _ = _`
    `num_of_big_int aux1 _ _ = _`
    `e_first \<le> e_last`
  have "num_of_big_int a__7 a_first ?L =
    ?x ^ nat (num_of_big_int e e_first (1 + (e_last - e_first))) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: power_mult_distrib [symmetric] mult_assoc)
      (simp add: add_commute mult_commute)
  with Base_inv show ?thesis by (simp add: add_commute)
qed

spark_end

end
