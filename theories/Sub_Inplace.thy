theory Sub_Inplace
imports Bignum
begin

lemma div_mod_eq: "(z::int) + x * (y mod b) + b * x * (y div b) = z + x * y"
proof -
  have "z + x * (y mod b) + b * x * (y div b) = z + x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  then show ?thesis by simp
qed

spark_open "$VCG_DIR/sub_inplace.siv"

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
    using [[fact "num_of_big_int a_init _ _ - num_of_big_int b _ _ = _ - _"]]
      [[fact "bounds _ _ _ _ a"]] [[fact "bounds _ _ _ _ b"]]
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
  using [[fact "num_of_big_int a_init _ _ - num_of_big_int b _ _ = _ - _"]]
  by (simp add: diff_add_eq)

spark_end

end
