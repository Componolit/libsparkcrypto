theory Add
imports Bignum
begin

lemma div_mod_eq:
  "z + (x::int) * (y mod b) + b * x * (y div b) = z + x * y"
  (is "?l = ?r")
proof -
  have "?l = z + x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  also have "... = ?r" by (simp add: ring_distribs)
  finally show ?thesis .
qed

lemma zdiv_geq: "0 < (n::int) \<Longrightarrow> n \<le> m \<Longrightarrow> m div n = (m - n) div n + 1"
  by (simp add: div_add_self2 [symmetric])

lemma le_zmod_geq: "(n::int) \<le> m \<Longrightarrow> m mod n = (m - n) mod n"
  by (simp add: mod_add_self2 [symmetric, of "m - n"])

lemma add_carry:
  "0 \<le> a \<Longrightarrow> 0 \<le> b \<Longrightarrow> a < B \<Longrightarrow> b < B \<Longrightarrow>
   num_of_bool ((a + b + num_of_bool c) mod B < a \<or>
     (a + b + num_of_bool c) mod B = a \<and> c) =
   (a + b + num_of_bool c) div B"
  by (cases "a + b + num_of_bool c < B")
    (auto simp add: mod_pos_pos_trivial div_pos_pos_trivial zdiv_geq
       le_zmod_geq not_less simp del: zmod_zsub_self
       split add: num_of_bool_split)


spark_open "$VCG_DIR/lsc_/bignum/add.siv" (lsc__bignum)

spark_vc procedure_add_3
  by simp

spark_vc procedure_add_6
  using
    `loop__1__i \<le> a_last`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
    `b__index__subtype__1__first \<le> b_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
    `c__index__subtype__1__last \<le> 2147483647`
    `c__index__subtype__1__first \<le> c_first`
  by simp_all

spark_vc procedure_add_10
  using
    `num_of_big_int b b_first (loop__1__i - a_first) +
    num_of_big_int c _ _ = _ + _`
    `bounds _ _ _ _ b` `bounds _ _ _ _ c`
    `b__index__subtype__1__first \<le> b_first`
    `c__index__subtype__1__first \<le> c_first`
    `a_first \<le> loop__1__i`
    `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
    `c_first + (loop__1__i - a_first) \<le> c__index__subtype__1__last`
    `word_of_boolean carry = num_of_bool carry`
  by (simp add: diff_add_eq [symmetric] nat_add_distrib
    add_carry div_mod_eq ring_distribs)

spark_vc procedure_add_12
  using `num_of_big_int b _ _ + num_of_big_int c _ _ = _ + _`
  by (simp add: diff_add_eq)

spark_end


spark_open "$VCG_DIR/lsc_/bignum/add_inplace.siv" (lsc__bignum)

spark_vc procedure_add_inplace_3
  by simp

spark_vc procedure_add_inplace_5
  using
    `loop__1__i \<le> a_last`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
    `a_first \<le> loop__1__i`
    `b__index__subtype__1__first \<le> b_first`
  by simp_all

spark_vc procedure_add_inplace_9
proof -
  from `a_first \<le> loop__1__i`
  have "num_of_big_int a_init a_first (loop__1__i + 1 - a_first) +
    num_of_big_int b b_first (loop__1__i + 1 - a_first) =
    num_of_big_int a_init a_first (loop__1__i - a_first) +
    num_of_big_int b b_first (loop__1__i - a_first) +
    (Base ^ nat (loop__1__i - a_first) * a_init loop__1__i +
     Base ^ nat (loop__1__i - a_first) * b (b_first + (loop__1__i - a_first)))"
    by (simp add: diff_add_eq [symmetric])
  moreover from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
    using
      `num_of_big_int a_init a_first (loop__1__i - a_first) +
       num_of_big_int b _ _ = _ + _`
      `bounds _ _ _ _ a` `bounds _ _ _ _ b`
      `a__index__subtype__1__first \<le> a_first`
      `b__index__subtype__1__first \<le> b_first`
      `a_first \<le> loop__1__i`
      `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
      `loop__1__i \<le> a__index__subtype__1__last`
      `word_of_boolean carry = num_of_bool carry`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib
      add_carry div_mod_eq ring_distribs)
next
  from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  show ?C2 by simp
qed

spark_vc procedure_add_inplace_11
  using `num_of_big_int a_init _ _ + num_of_big_int b _ _ = _ + _`
  by (simp add: diff_add_eq)

spark_end


spark_open "$VCG_DIR/lsc_/bignum/mod_add.siv" (lsc__bignum)

spark_vc procedure_mod_add_3
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
  have "num_of_big_int b b_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  moreover from
    `bounds _ _ _ _ c`
    `c__index__subtype__1__first \<le> c_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
  have "num_of_big_int c c_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  ultimately have "num_of_big_int a__1 a_first ?k < num_of_big_int m m_first ?k"
    using
      `num_of_big_int b _ _ \<le> num_of_big_int m _ _ \<or>
       num_of_big_int c _ _ \<le> num_of_big_int m _ _`
      `num_of_big_int b _ _ + num_of_big_int c _ _ = _`
    by auto
  moreover from
    `bounds _ _ _ _ a__1` `bounds _ _ _ _ a__2`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__1 a_first ?k"
    "0 \<le> num_of_big_int a__2 a_first ?k"
    by (simp_all add: num_of_lint_lower)
  ultimately show ?thesis
  using
    `num_of_big_int b _ _ + num_of_big_int c _ _ = _`
    `num_of_big_int a__1 _ _ - num_of_big_int m _ _ = _`
    by (cases carry__2) simp_all
qed

spark_vc procedure_mod_add_4
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ a__1`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "num_of_big_int a__1 a_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  with `num_of_big_int b _ _ + num_of_big_int c _ _ = _`
  show ?thesis by simp
qed

spark_end


spark_open "$VCG_DIR/lsc_/bignum/mod_add_inplace.siv" (lsc__bignum)

spark_vc procedure_mod_add_inplace_3
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "num_of_big_int a a_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  moreover from
    `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
  have "num_of_big_int b b_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  ultimately have "num_of_big_int a__1 a_first ?k < num_of_big_int m m_first ?k"
    using
      `num_of_big_int a _ _ \<le> num_of_big_int m _ _ \<or>
       num_of_big_int b _ _ \<le> num_of_big_int m _ _`
      `num_of_big_int a _ _ + num_of_big_int b _ _ = _`
    by auto
  moreover from
    `bounds _ _ _ _ a__1` `bounds _ _ _ _ a__2`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__1 a_first ?k"
    "0 \<le> num_of_big_int a__2 a_first ?k"
    by (simp_all add: num_of_lint_lower)
  ultimately show ?thesis
  using
    `num_of_big_int a _ _ + num_of_big_int b _ _ = _`
    `num_of_big_int a__1 _ _ - num_of_big_int m _ _ = _`
    by (cases carry__2) simp_all
qed

spark_vc procedure_mod_add_inplace_4
proof -
  let ?k = "a_last - a_first + 1"
  from
    `bounds _ _ _ _ a__1`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "num_of_big_int a__1 a_first ?k < Base ^ nat ?k"
    by (simp add: num_of_lint_upper)
  with `num_of_big_int a _ _ + num_of_big_int b _ _ = _`
  show ?thesis by simp
qed

spark_end

end
