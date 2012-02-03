theory Sub
imports Bignum
begin

lemma div_mod_eq: "(z::int) + x * (y mod b) + b * x * (y div b) = z + x * y"
proof -
  have "z + x * (y mod b) + b * x * (y div b) = z + x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  then show ?thesis by simp
qed

lemma sub_carry:
  assumes "0 \<le> a" and "a < B" and "0 \<le> b" and "b < B"
  shows "num_of_bool (a < b \<or> a = b \<and> c) =
   - ((a - b - num_of_bool c) div B)"
proof (cases "a < b")
  case True
  with assms have "1 - (a - b) < B \<or> 1 - (a - b) = B" by auto
  with True
    zdiv_zminus1_eq_if [of _ "1 - (a - b)"]
    zdiv_zminus1_eq_if [of _ "b - a"]
  show ?thesis
    by (auto simp add: zdiv_eq_0_iff mod_pos_pos_trivial
      split add: num_of_bool_split)
next
  case False
  with assms show ?thesis
    by (auto simp add: zdiv_eq_0_iff div_eq_minus1 split add: num_of_bool_split)
qed


spark_open "$VCG_DIR/lsc_/bignum/sub.siv" (lsc__bignum)

spark_vc procedure_sub_3
  by simp

spark_vc procedure_sub_6
  using
    `a_first \<le> loop__1__i`
    `loop__1__i \<le> a_last`
    `b__index__subtype__1__first \<le> b_first`
    `0 \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
    `c__index__subtype__1__first \<le> c_first`
    `0 \<le> c_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
    `c__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_sub_9
  using
    `num_of_big_int b _ _ - num_of_big_int c _ _ = _ - _`
    `bounds _ _ _ _ b` `bounds _ _ _ _ c`
    `b__index__subtype__1__first \<le> b_first`
    `c__index__subtype__1__first \<le> c_first`
    `a_first \<le> loop__1__i`
    `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
    `c_first + (loop__1__i - a_first) \<le> c__index__subtype__1__last`
    `word_of_boolean carry = num_of_bool carry`
  by (simp add: diff_add_eq [symmetric] nat_add_distrib
    sub_carry [of _ Base] div_mod_eq ring_distribs)

spark_vc procedure_sub_11
  using `num_of_big_int b _ _ - num_of_big_int c _ _ = _ - _`
  by (simp add: diff_add_eq)

spark_end


spark_open "$VCG_DIR/lsc_/bignum/sub_inplace.siv" (lsc__bignum)

spark_vc procedure_sub_inplace_3
  by simp

spark_vc procedure_sub_inplace_5
  using `loop__1__i \<le> a_last`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp
  
spark_vc procedure_sub_inplace_6
  using `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
  by simp_all

spark_vc procedure_sub_inplace_9
proof -
  from `a_first \<le> loop__1__i`
  have "num_of_big_int a_init a_first (loop__1__i + 1 - a_first) -
    num_of_big_int b b_first (loop__1__i + 1 - a_first) =
    num_of_big_int a_init a_first (loop__1__i - a_first) -
    num_of_big_int b b_first (loop__1__i - a_first) +
    (Base ^ nat (loop__1__i - a_first) * a_init loop__1__i -
     Base ^ nat (loop__1__i - a_first) * b (b_first + (loop__1__i - a_first)))"
    by (simp add: diff_add_eq [symmetric])
  moreover from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
    using `num_of_big_int a_init _ _ - num_of_big_int b _ _ = _ - _`
      `bounds _ _ _ _ a` `bounds _ _ _ _ b`
      `a__index__subtype__1__first \<le> a_first`
      `b__index__subtype__1__first \<le> b_first`
      `a_first \<le> loop__1__i`
      `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
      `loop__1__i \<le> a__index__subtype__1__last`
      `word_of_boolean carry = num_of_bool carry`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib
      sub_carry [of _ Base] div_mod_eq ring_distribs)
next
  from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  show ?C2 by simp
qed

spark_vc procedure_sub_inplace_11
  using `num_of_big_int a_init _ _ - num_of_big_int b _ _ = _ - _`
  by (simp add: diff_add_eq)

spark_end


spark_open "$VCG_DIR/lsc_/bignum/mod_sub.siv" (lsc__bignum)

spark_vc procedure_mod_sub_3
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
  have "0 \<le> num_of_big_int b b_first ?k"
    by (simp add: num_of_lint_lower)
  with
    `num_of_big_int c _ _ \<le> num_of_big_int m _ _`
    `num_of_big_int b _ _ - num_of_big_int c _ _ = _`
  have "Base ^ nat ?k \<le>
    num_of_big_int a__1 a_first ?k + num_of_big_int m m_first ?k"
    by simp
  moreover from
    `bounds _ _ _ _ a__1` `bounds _ _ _ _ a__2`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "num_of_big_int a__1 a_first ?k < Base ^ nat ?k"
    "num_of_big_int a__2 a_first ?k < Base ^ nat ?k"
    by (simp_all add: num_of_lint_upper)
  ultimately show ?thesis
  using
    `num_of_big_int b _ _ - num_of_big_int c _ _ = _`
    `num_of_big_int a__1 _ _ + num_of_big_int m _ _ = _`
    by (cases carry__2) simp_all
qed

spark_vc procedure_mod_sub_4
proof -
  from
    `bounds _ _ _ _ a__1`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__1 a_first (a_last - a_first + 1)"
    by (simp add: num_of_lint_lower)
  with `num_of_big_int b _ _ - num_of_big_int c _ _ = _`
  show ?thesis by simp
qed

spark_end


spark_open "$VCG_DIR/lsc_/bignum/mod_sub_inplace.siv" (lsc__bignum)

spark_vc procedure_mod_sub_inplace_3
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a a_first ?k"
    by (simp add: num_of_lint_lower)
  with
    `num_of_big_int b _ _ \<le> num_of_big_int m _ _`
    `num_of_big_int a _ _ - num_of_big_int b _ _ = _`
  have "Base ^ nat ?k \<le>
    num_of_big_int a__1 a_first ?k + num_of_big_int m m_first ?k"
    by simp
  moreover from
    `bounds _ _ _ _ a__1` `bounds _ _ _ _ a__2`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "num_of_big_int a__1 a_first ?k < Base ^ nat ?k"
    "num_of_big_int a__2 a_first ?k < Base ^ nat ?k"
    by (simp_all add: num_of_lint_upper)
  ultimately show ?thesis
  using
    `num_of_big_int a _ _ - num_of_big_int b _ _ = _`
    `num_of_big_int a__1 _ _ + num_of_big_int m _ _ = _`
    by (cases carry__2) simp_all
qed

spark_vc procedure_mod_sub_inplace_4
proof -
  from
    `bounds _ _ _ _ a__1`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__1 a_first (a_last - a_first + 1)"
    by (simp add: num_of_lint_lower)
  with `num_of_big_int a _ _ - num_of_big_int b _ _ = _`
  show ?thesis by simp
qed

spark_end

end
