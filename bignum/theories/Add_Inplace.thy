theory Add_Inplace
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

spark_open "$VCG_DIR/add_inplace.siv"

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

end
