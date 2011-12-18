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

spark_open "$VCG_DIR/lsc_/bignum/double_inplace.siv"

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

spark_vc procedure_double_inplace_8
proof -
  from `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> a__index__subtype__1__last`
  have "0 \<le> a loop__1__i" "a loop__1__i \<le> Base - 1"
    by simp_all
  then have "num_of_bool (a loop__1__i AND 2147483648 \<noteq> 0) =
    (a loop__1__i * 2 + num_of_bool carry) div (2 * 2147483648)"
    by (rule double_inplace_carry)
  moreover from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  have "a_init loop__1__i = a loop__1__i" by simp
  ultimately show ?C1
    using `a_first \<le> loop__1__i`
      `num_of_big_int a_init _ _ * 2 = num_of_big_int a _ _ + _`
      `lsc__types__shl32 _ _ = _`
      `word_of_boolean carry = num_of_bool carry`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib div_mod_eq ring_distribs)
next
  from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
    `loop__1__i \<le> a_last`
  show ?C2 by simp
qed

spark_vc procedure_double_inplace_10
  using `num_of_big_int a_init _ _ * 2 = num_of_big_int a _ _ + _`
  by (simp add: diff_add_eq)

spark_end

end
