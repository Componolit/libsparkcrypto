theory Double_Inplace
imports Bignum
begin

lemma num_of_bool_mod2: "num_of_bool (x mod 2 \<noteq> 0) = x mod 2"
  by (simp split: num_of_bool_split) arith

lemma div_mod_eq: "(x::int) * (y mod b) + b * x * (y div b) = x * y"
proof -
  have "x * (y mod b) + b * x * (y div b) = x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  then show ?thesis by simp
qed

spark_open "out/bignum/double_inplace.siv"

spark_vc procedure_double_inplace_3
  by simp

lemma double_inplace_carry:
  assumes "0 \<le> a" and "a \<le> Base - 1"
  shows "num_of_bool (a AND 2147483648 \<noteq> 0) =
    (a * 2 + num_of_bool carry) div (2 * 2147483648)"
proof -
  let ?X = 2147483648
  from AND_div_mod [of _ 31]
  have "(a AND ?X \<noteq> 0) = (a div ?X mod 2 \<noteq> 0)" (is "?l = ?r")
    by simp
  then have "num_of_bool ?l = num_of_bool ?r" by simp
  also note num_of_bool_mod2
  also from `a \<le> Base - 1` have "a div ?X \<le> 1" by simp
  with `0 \<le> a` have "a div ?X mod 2 = a div ?X"
    by (simp add: mod_pos_pos_trivial)
  also have "a div ?X = (a * 2 + num_of_bool carry) div (2 * ?X)"
    by (simp only: zdiv_zmult2_eq)
      (simp add: zdiv_zadd1_eq [of "a * 2" "num_of_bool carry" 2]
         split: num_of_bool_split)
  finally show ?thesis .
qed

spark_vc procedure_double_inplace_4
proof -
  from H3 H6 H7 H9 H21 have "0 \<le> a loop__1__i" "a loop__1__i \<le> Base - 1"
    by simp_all
  then have "num_of_bool (a loop__1__i AND 2147483648 \<noteq> 0) =
    (a loop__1__i * 2 + num_of_bool carry) div (2 * 2147483648)"
    by (rule double_inplace_carry)
  moreover from H2 `loop__1__i < a_last`
  have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
    using `a_first \<le> loop__1__i` H1 H15 H18
    by (simp add: diff_add_eq [symmetric] nat_add_distrib pull_mods div_mod_eq ring_distribs)
next
  from H2 `loop__1__i < a_last`
  show ?C2 by simp
qed

spark_vc procedure_double_inplace_9
proof -
  from H3 H11 H16 have "0 \<le> a a_last" "a a_last \<le> Base - 1"
    by simp_all
  then have "num_of_bool (a a_last AND 2147483648 \<noteq> 0) =
    (a a_last * 2 + num_of_bool carry) div (2 * 2147483648)"
    by (rule double_inplace_carry)
  moreover from H2
  have "a_init a_last = a a_last" by simp
  ultimately show ?thesis
    using `a_first \<le> a_last` H1 H22 H25
    by (simp add: nat_add_distrib pull_mods div_mod_eq ring_distribs)
qed

spark_end

end
