theory SHR_Inplace
imports Bignum
begin

lemma zdiv_zmod_equality': "(m::int) div n * n = m - m mod n"
  by (simp add: minus_div_mult_eq_mod [symmetric])

lemma two_words_upper:
  assumes "(x::int) < a" "y < b" "0 \<le> a"
  shows "x + a * y < a * b"
proof -
  from `y < b` have "y \<le> b - 1" by simp
  then have "a * y \<le> a * (b - 1)" using `0 \<le> a`
    by (rule mult_left_mono)
  with `x < a` show ?thesis by (simp add: ring_distribs)
qed

spark_open "$VCG_DIR/lsc_/bignum/shr_inplace" (lsc__bignum)

spark_vc procedure_shr_inplace_4
  by simp

spark_vc procedure_shr_inplace_11
proof -
  have eq: "a_last - (loop__1__i - 1) = 1 + (a_last - loop__1__i)"
    by simp
  have
    "(a loop__1__i div 2 ^ nat k + h1 * 2 ^ nat (32 - k)) mod Base * 2 ^ nat k +
     a loop__1__i mod 2 ^ nat k =
     (a loop__1__i div 2 ^ nat k * 2 ^ nat k +
      h1 * 2 ^ nat (32 - k) * 2 ^ nat k mod (Base * 2 ^ nat k)) mod
       (Base * 2 ^ nat k) +
     a loop__1__i mod 2 ^ nat k"
    by (simp add: mod_mult_mult2 ring_distribs [symmetric])
  also from `0 \<le> k` `k \<le> 32`
  have "h1 * 2 ^ nat (32 - k) * 2 ^ nat k = Base * h1"
    by (simp add: nat_diff_distrib power_add [symmetric])
  also have "Base * h1 mod (Base * 2 ^ nat k) = Base * (h1 mod 2 ^ nat k)"
    by simp
  also from `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> a__index__subtype__1__last`
  have "a loop__1__i < Base" "0 \<le> a loop__1__i" by simp_all
  then have "a loop__1__i div 2 ^ nat k * 2 ^ nat k < Base"
    by (auto simp add: zdiv_zmod_equality'
      intro: add_less_le_mono [of _ _ "- (a loop__1__i mod 2 ^ nat k)" 0,
      simplified])
  then have "a loop__1__i div 2 ^ nat k * 2 ^ nat k +
      Base * (h1 mod 2 ^ nat k) < Base * 2 ^ nat k"
    by (rule two_words_upper) simp_all
  with `0 \<le> a loop__1__i`
  have "(a loop__1__i div 2 ^ nat k * 2 ^ nat k +
      Base * (h1 mod 2 ^ nat k)) mod (Base * 2 ^ nat k) =
    a loop__1__i div 2 ^ nat k * 2 ^ nat k + Base * (h1 mod 2 ^ nat k)"
    by (simp add: mod_pos_pos_trivial
      mult_nonneg_nonneg pos_imp_zdiv_nonneg_iff)
  finally
  have "(a loop__1__i div 2 ^ nat k + h1 * 2 ^ nat (32 - k)) mod Base * 2 ^ nat k +
    a loop__1__i mod 2 ^ nat k =
    a loop__1__i + Base * (h1 mod 2 ^ nat k)"
    by (simp add: div_mult_mod_eq)
  moreover from
    `\<forall>j. a_first \<le> j \<and> j \<le> loop__1__i \<longrightarrow> a j = a_init j`
    `a_first \<le> loop__1__i`
  have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
  using
    `loop__1__i \<le> a_last`
    `num_of_big_int a_init (loop__1__i + 1) (a_last - loop__1__i) = _`
    `lsc__types__shr32 (a loop__1__i) k = a loop__1__i sdiv 2 ^ nat k`
    `lsc__types__shl32 h1 (32 - k) = h1 * 2 ^ nat (32 - k) mod Base`
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> a__index__subtype__1__last`
    by (simp add: eq ring_distribs sdiv_pos_pos)

  from `\<forall>j. a_first \<le> j \<and> j \<le> loop__1__i \<longrightarrow> a j = a_init j`
  show ?C2 by simp
qed

spark_vc procedure_shr_inplace_13
  using
    `num_of_big_int a_init a_first (a_last - (a_first - 1)) =
     num_of_big_int a a_first (a_last - (a_first - 1)) * 2 ^ nat k + h1 mod 2 ^ nat k`
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  by (simp add: diff_diff_eq2 diff_add_eq sdiv_pos_pos
    num_of_lint_lower mult_nonneg_nonneg zdiv_zadd1_eq)

spark_end

end
