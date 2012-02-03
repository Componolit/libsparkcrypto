theory Is_Zero
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/is_zero.siv" (lsc__bignum)

spark_vc function_is_zero_3
  by simp

spark_vc function_is_zero_4
  using `a loop__1__i = 0` `a_first \<le> loop__1__i`
  by (simp add: diff_add_eq [symmetric])

spark_vc function_is_zero_7
proof -
  from 
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `loop__1__i \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a a_first (loop__1__i - a_first)"
    by (simp add: num_of_lint_lower)
  moreover from
    `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> a__index__subtype__1__last`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> a loop__1__i"
    "0 \<le> num_of_big_int a (loop__1__i + 1) (a_last - loop__1__i)"
    by (simp_all add: num_of_lint_lower)
  with `a loop__1__i \<noteq> 0`
  have "0 < a loop__1__i +
      Base * num_of_big_int a (loop__1__i + 1) (a_last - loop__1__i)"
    by simp
  then have "0 * 0 < Base ^ nat (loop__1__i - a_first) * \<dots>"
    by - (rule mult_strict_mono, simp_all)
  ultimately have "num_of_big_int a a_first
    (loop__1__i - a_first + (1 + (a_last - loop__1__i))) \<noteq> 0"
    using `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    by (simp only: num_of_lint_sum) simp
  then show ?thesis by (simp add: add_ac)
qed

spark_vc function_is_zero_8
  using `a_first \<le> a_last` `a a_last = 0`
  by simp

spark_end

end
