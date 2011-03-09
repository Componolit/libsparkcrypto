theory Less
imports Bignum
begin

spark_open "$VCG_DIR/less.siv"

spark_vc function_less_3
  by simp

spark_vc function_less_4
proof -
  from H1 H31 `loop__1__i \<le> a_last`
  have "num_of_big_int a loop__1__i (1 + (a_last - loop__1__i)) =
    num_of_big_int b (b_first + (loop__1__i - a_first)) (1 + (a_last - loop__1__i))"
    by simp
  then show ?thesis by (simp add: sign_simps)
qed

spark_vc function_less_5
  using H17 H37 `loop__1__i \<le> a_last`
  by simp

spark_vc function_less_6
  using H14 H17 `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
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
  from H2 H10 H31 have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower)
  moreover from H2 H10 H31 have "?a' < ?c"
    by (simp add: num_of_lint_upper)
  moreover from H7 H14 H29 have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower)
  moreover from H1 H32 `loop__1__i \<le> a_last`
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
  from H7 H14 H29 have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower)
  moreover from H7 H14 H29 have "?b' < ?c"
    by (simp add: num_of_lint_upper)
  moreover from H2 H10 H31 have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower)
  moreover from H1 H32 `loop__1__i \<le> a_last`
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
  from H1 H30 `a_first \<le> a_last`
  have "num_of_big_int a a_first (1 + (a_last - a_first)) =
    num_of_big_int b b_first (1 + (a_last - a_first))"
    by simp
 then show ?thesis by (simp add: add_commute)
qed

spark_end

end
