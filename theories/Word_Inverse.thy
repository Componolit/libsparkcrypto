theory Word_Inverse
imports Bignum
begin

lemma div_minus_self:
  assumes "(b::int) \<noteq> 0"
  shows "(a - b) div b = a div b - 1"
proof -
  from assms have "a div b = (a - b) div b + 1"
    by (simp add: div_add_self2 [symmetric])
  then show ?thesis by simp
qed

lemma zdiv_zmod_equality': "(m::int) div n * n = m - m mod n"
  by (simp add: zmod_zdiv_equality')

spark_open "$VCG_DIR/word_inverse.siv"

spark_proof_functions
  gcd = gcd

spark_vc function_word_inverse_2
  using `m mod 2 = 1` `0 \<le> m`
  by auto

spark_vc function_word_inverse_5
proof -
  note m_upper = `m \<le> _`
  have "(- m) mod Base = (Base - m) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  with `0 < m` m_upper
  have minus_m: "(- m) mod Base = Base - m"
    by (simp add: mod_pos_pos_trivial)
  then have minus_m': "- m mod Base mod m = Base mod m"
    by simp
  also from `0 < m` have "Base mod m < m" by simp
  with m_upper have "Base mod m < Base" by simp
  with `0 < m` have "Base mod m = (Base - Base div m * m) mod Base"
    by (simp add: zmod_zdiv_equality' [symmetric]
      mod_pos_pos_trivial)
  also have "\<dots> = - (Base div m * m) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  finally show ?C1 using `0 < m` m_upper
    by (simp add: pull_mods minus_m sdiv_pos_pos div_minus_self)

  from odd_coprime [OF `m mod 2 = 1`, of 32]
  have "coprime Base m"  by (simp add: gcd_commute_int)
  also note gcd_red_int
  finally show ?C2 using minus_m' by simp
qed

spark_vc function_word_inverse_6
proof -
  from `0 < q * m mod Base`
  have "p * m mod Base mod (q * m mod Base) < q * m mod Base"
    by simp
  then have "p * m mod Base mod (q * m mod Base) < Base" by simp
  with `0 < q * m mod Base` have "p * m mod Base mod (q * m mod Base) =
    (p * m - p * m mod Base div (q * m mod Base) * (q * m mod Base)) mod Base"
    by (simp add: zdiv_zmod_equality'
      zdiff_zmod_left [of "p * m", symmetric] mod_pos_pos_trivial)
  also note zdiff_zmod_right
  also note mod_mult_right_eq
  finally show ?C1
    by (simp add: pull_mods sdiv_pos_pos ring_distribs mult_assoc)
next
  from `coprime (p * m mod Base) (q * m mod Base)`
  show ?C2 by (simp add: gcd_red_int [symmetric])
qed

spark_vc function_word_inverse_14
  using `coprime (p * m mod Base) 0`
  by (simp add: pull_mods zdiff_zmod_right [of _ "p * m", symmetric])

spark_end

end
