theory Less
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/less" (lsc__bignum)

spark_vc function_less_3
  by simp

spark_vc function_less_4
proof -
  from `loop__1__i \<le> a_last`
    `num_of_big_int a _ _ =  num_of_big_int b _ _`
    `b (b_first + (loop__1__i - a_first)) = a loop__1__i`
  have "num_of_big_int a loop__1__i (1 + (a_last - loop__1__i)) =
    num_of_big_int b (b_first + (loop__1__i - a_first)) (1 + (a_last - loop__1__i))"
    by simp
  then show ?thesis by (simp add: sign_simps)
qed

spark_vc function_less_5
  using `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647` `loop__1__i \<le> a_last`
  by simp

spark_vc function_less_6
  using `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
  by simp_all

lemma msw_less:
  assumes "(0::int) \<le> a'" "a' < c" "0 \<le> b'" "a < b"
  shows "a' + c * a < b' + c * b"
proof -
  from `a' < c` have "a' + c * a < c + c * a" by simp
  also from `a < b` have "1 + a \<le> b" by simp
  with `0 \<le> a'` `a' < c` have "c * (1 + a) \<le> c * b"
    by (simp add: mult_left_mono)
  then have "c + c * a \<le> c * b" by (simp add: ring_distribs)
  also from `0 \<le> b'` have "c * b \<le> b' + c * b" by simp
  finally show ?thesis .
qed

spark_vc function_less_9
proof -
  let ?l' = "loop__1__i - a_first"
  let ?l = "1 + (a_last - loop__1__i)"
  let ?a' = "num_of_big_int a a_first ?l'"
  let ?b' = "num_of_big_int b b_first ?l'"
  let ?a = "num_of_big_int a loop__1__i ?l"
  let ?b = "num_of_big_int b (b_first + ?l') ?l"
  let ?c = "Base ^ nat ?l'"
  note a_in_range = `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `loop__1__i \<le> a__index__subtype__1__last`
  note b_in_range = `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
  from a_in_range have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower)
  moreover from a_in_range have "?a' < ?c"
    by (simp add: num_of_lint_upper)
  moreover from b_in_range have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower)
  moreover from
    `num_of_big_int a _ _ = num_of_big_int b _ _`
    `a loop__1__i < b (b_first + (loop__1__i - a_first))`
    `loop__1__i \<le> a_last`
  have "?a < ?b" by simp
  ultimately have "?a' + ?c * ?a < ?b' + ?c * ?b"
    by (rule msw_less)
  then have "num_of_big_int a a_first (?l' + ?l) <
    num_of_big_int b b_first (?l' + ?l)"
    using `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    by (simp only: num_of_lint_sum) simp
  then show ?thesis by (simp add: sign_simps)
qed

spark_vc function_less_10
proof -
  let ?l' = "loop__1__i - a_first"
  let ?l = "1 + (a_last - loop__1__i)"
  let ?a' = "num_of_big_int a a_first ?l'"
  let ?b' = "num_of_big_int b b_first ?l'"
  let ?a = "num_of_big_int a loop__1__i ?l"
  let ?b = "num_of_big_int b (b_first + ?l') ?l"
  let ?c = "Base ^ nat ?l'"
  note a_in_range = `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `loop__1__i \<le> a__index__subtype__1__last`
  note b_in_range = `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
  from b_in_range have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower)
  moreover from b_in_range have "?b' < ?c"
    by (simp add: num_of_lint_upper)
  moreover from a_in_range have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower)
  moreover from
    `num_of_big_int a _ _ = num_of_big_int b _ _`
    `b (b_first + (loop__1__i - a_first)) < a loop__1__i`
    `loop__1__i \<le> a_last`
  have "?b < ?a" by simp
  ultimately have "?b' + ?c * ?b < ?a' + ?c * ?a"
    by (rule msw_less)
  then have "num_of_big_int b b_first (?l' + ?l) <
    num_of_big_int a a_first (?l' + ?l)"
    using `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    by (simp only: num_of_lint_sum) simp
  then show ?thesis by (simp add: sign_simps)
qed

spark_vc function_less_11
proof -
  from `num_of_big_int a _ _ = num_of_big_int b _ _`
    `b b_first = a a_first` `a_first \<le> a_last`
  have "num_of_big_int a a_first (1 + (a_last - a_first)) =
    num_of_big_int b b_first (1 + (a_last - a_first))"
    by simp
 then show ?thesis by (simp add: add_commute)
qed

spark_end

end
