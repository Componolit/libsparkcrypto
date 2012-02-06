theory Is_Zero
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/is_zero.siv" (lsc__bignum)

spark_vc function_is_zero_4
  using `a loop__1__i = 0`
  by (auto simp add: le_less)

spark_vc function_is_zero_7
  using
    num_of_lint_equals_iff [where B="\<lambda>i. 0"]
    `bounds _ _ _ _ a`
    `a_first \<le> loop__1__i`
    `loop__1__i \<le> a_last`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
    `a loop__1__i \<noteq> 0`
  by (auto simp add: num_of_lint_all0 simp del: num_of_lint_sum)

spark_vc function_is_zero_8
  using
    num_of_lint_equals_iff [where B="\<lambda>i. 0"]
    `bounds _ _ _ _ a`
    `a_first \<le> a_last`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
    `a a_last = 0`
  by (auto simp add: num_of_lint_all0)

spark_end

end
