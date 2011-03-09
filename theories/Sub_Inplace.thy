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

spark_vc procedure_sub_inplace_4
proof -
  from `a_first \<le> loop__1__i`
  have "num_of_big_int a_init a_first (loop__1__i + 1 - a_first) -
    num_of_big_int b b_first (loop__1__i + 1 - a_first) =
    num_of_big_int a_init a_first (loop__1__i - a_first) -
    num_of_big_int b b_first (loop__1__i - a_first) +
    (Base ^ nat (loop__1__i - a_first) * a_init loop__1__i -
     Base ^ nat (loop__1__i - a_first) * b (b_first + (loop__1__i - a_first)))"
    by (simp add: diff_add_eq [symmetric])
  moreover from H2 H36 have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
    using H1 H3 H8 H11 H15 H21 H28 H30 H33
    by (simp add: diff_add_eq [symmetric] nat_add_distrib pull_mods
      sub_carry [of _ Base] div_mod_eq ring_distribs)
next
  from H2 `loop__1__i < a_last`
  show ?C2 by simp
qed

spark_vc procedure_sub_inplace_5
  using `loop__1__i \<le> a_last` H18 H36
  by simp
  
spark_vc procedure_sub_inplace_6
  using `a_first \<le> loop__1__i` `loop__1__i \<le> a_last` H15 H18
  by simp_all

spark_vc procedure_sub_inplace_10
proof -
  from `a_first \<le> a_last`
  have "num_of_big_int a_init a_first (a_last - a_first + 1) -
    num_of_big_int b b_first (a_last - a_first + 1) =
    num_of_big_int a_init a_first (a_last - a_first) -
    num_of_big_int b b_first (a_last - a_first) +
    (Base ^ nat (a_last - a_first) * a_init a_last -
     Base ^ nat (a_last - a_first) * b (b_first + (a_last - a_first)))"
    by simp
  moreover from H2 have "a_init a_last = a a_last" by simp
  ultimately show ?thesis
    using H1 H3 H8 H11 H15 H22 H29 H31 H34
    by (simp add: diff_add_eq [symmetric] nat_add_distrib pull_mods
      sub_carry [of _ Base] div_mod_eq ring_distribs)
qed

spark_end

end
