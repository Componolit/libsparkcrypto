theory Equal
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/equal" (lsc__bignum)

spark_vc function_equal_4
  using `a loop__1__i = b (b_first + (loop__1__i - a_first))`
  by (auto simp add: le_less)

spark_vc function_equal_5
  using
    `a_first \<le> loop__1__i`
    `loop__1__i \<le> a_last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc function_equal_7
  using
    `bounds _ _ _ _ a`
    `bounds _ _ _ _ b`
    `a_first \<le> loop__1__i`
    `loop__1__i \<le> a_last`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `a loop__1__i \<noteq> b (b_first + (loop__1__i - a_first))`
  by (auto simp add: num_of_lint_equals_iff simp del: num_of_lint_sum)

spark_vc function_equal_8
  using
    `bounds _ _ _ _ a`
    `bounds _ _ _ _ b`
    `a_first \<le> a_last`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `a a_last = b (b_first + (a_last - a_first))`
  by (auto simp add: num_of_lint_equals_iff)

spark_end

end
