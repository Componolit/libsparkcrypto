theory Add_Mult_Inplace
imports Bignum
begin

lemma div_mod_eq: "(x::int) * (y mod b) + b * x * (y div b) = x * y"
proof -
  have "x * (y mod b) + b * x * (y div b) = x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  then show ?thesis by simp
qed

spark_open "out/bignum/add_mult_inplace.siv"

spark_vc procedure_add_mult_inplace_4
  by simp

spark_vc procedure_add_mult_inplace_5
proof -
  let ?i = "loop__1__i - a_first"
  let ?a = "a loop__1__i + b (b_first + ?i) * c + carry2"
  note inv = [[fact "num_of_big_int a_init _ _ + num_of_big_int b _ _ * c = _",
    simplified pow_simp_Base]]
  note shr = [[fact "types__shr _ _ = _"]]
  note a_in_range = [[fact "bounds _ _ _ _ a"]]
  note b_in_range = [[fact "bounds _ _ _ _ b"]]
  from `a_first \<le> loop__1__i`
  have "num_of_big_int a_init a_first (loop__1__i + 1 - a_first) +
    num_of_big_int b b_first (loop__1__i + 1 - a_first) * c =
    num_of_big_int a_init a_first ?i +
    num_of_big_int b b_first ?i * c +
    Base ^ nat ?i * a_init loop__1__i +
    Base ^ nat ?i * b (b_first + ?i) * c"
    by (simp add: diff_add_eq [symmetric] ring_distribs)
  also from `a_first \<le> loop__1__i` `loop__1__i < a_last - 1`
    `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
  have "a_init loop__1__i = a loop__1__i" by simp
  finally show ?C1
    using inv shr `a_first \<le> loop__1__i`
      `a__index__subtype__1__first \<le> loop__1__i`
      `loop__1__i \<le> a__index__subtype__1__last`
      `b__index__subtype__1__first \<le> b_first + ?i`
      `b_first + ?i \<le> b__index__subtype__1__last`
      a_in_range b_in_range `0 \<le> c` `0 \<le> carry2`
    by (simp only: pow_simp_Base)
      (simp add: diff_add_eq [symmetric] nat_add_distrib ring_distribs
        sdiv_pos_pos mult_nonneg_nonneg div_mod_eq)
next
  from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
  show ?C2 by simp
qed

spark_vc procedure_add_mult_inplace_6
proof -
  note Hs = `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first - 1) \<le> b__index__subtype__1__last`
    `loop__1__i \<le> a_last - 1` `a_first \<le> loop__1__i`
    [[fact "bounds _ _ _ _ b"]]
    `b__index__subtype__1__last \<le> 2147483647`
  then show ?C1 ?C3 ?C4
    by simp_all
  from Hs have "b (b_first + (loop__1__i - a_first)) \<le> 4294967295"
    by simp
  then show ?C2 by simp
qed

spark_vc procedure_add_mult_inplace_9
proof -
  have "0 < Base" by simp
  from [[fact "types__shr _ _ = _"]]
    [[fact "a loop__1__i + _ + _ \<le> _", THEN zdiv_mono1, OF `0 < Base`]]
    [[fact "bounds _ _ _ _ a"]] [[fact "bounds _ _ _ _ b"]]
    `a__index__subtype__1__first \<le> loop__1__i`
    `loop__1__i \<le> a__index__subtype__1__last`
    `b__index__subtype__1__first \<le> b_first + (loop__1__i - a_first)`
    `b_first + (loop__1__i - a_first) \<le> b__index__subtype__1__last`
    `0 \<le> c` `0 \<le> carry2`
    show ?thesis by (simp add: sdiv_pos_pos mult_nonneg_nonneg)
qed

lemma add_carry:
  assumes "0 \<le> a" and "0 \<le> b" and "a < c" and "b < c"
  shows "num_of_bool ((a + b) mod c < b) = (a + b) div c"
proof (cases "a + b < c")
  case True
  with assms show ?thesis
    by (auto simp add: mod_pos_pos_trivial div_pos_pos_trivial
      split add: num_of_bool_split)
next
  case False
  with assms div_add_self2 [of c "a + b - c"]
    zmod_zsub_self [of "a + b" c, symmetric]
  show ?thesis
    by (auto simp add: not_less div_pos_pos_trivial
      mod_pos_pos_trivial simp del: zmod_zsub_self
      split add: num_of_bool_split)
qed

spark_vc procedure_add_mult_inplace_15
proof -
  let ?l = "a_last - 1 - a_first"
  let ?a = "a (a_last - 1) + b (b_first + ?l) * c + carry2"
  let ?carry = "num_of_bool ((a a_last + ?a div Base) mod Base < ?a div Base)"
  note inv = [[fact "num_of_big_int a_init _ _ + num_of_big_int b _ _ * c = _",
    simplified pow_simp_Base]]
  note a_init = `\<forall>k. a_last - 1 \<le> k \<and> k \<le> a_last \<longrightarrow> a k = a_init k`
  have "0 < Base" by simp
  have "num_of_big_int a_init a_first (a_last - a_first + 1) +
    num_of_big_int b b_first (a_last - a_first) * c =
    num_of_big_int a_init a_first (?l + (1 + 1)) +
    num_of_big_int b b_first (?l + 1) * c"
    by (simp add: add_ac)
  also from `a_first < a_last` a_init
  have "\<dots> = num_of_big_int a_init a_first ?l +
    num_of_big_int b b_first ?l * c +
    Base ^ nat ?l * (a (a_last - 1) + Base * a a_last) +
    Base ^ nat ?l * b (b_first + ?l) * c"
    by (simp only: num_of_lint_sum) (simp add: ring_distribs del: arith_simps)
  also note inv
  also have "num_of_big_int a a_first ?l +
    Base ^ nat ?l * carry2 +
    Base ^ nat ?l * (a (a_last - 1) + Base * a a_last) +
    Base ^ nat ?l * b (b_first + ?l) * c =
    num_of_big_int a a_first ?l +
    Base ^ nat ?l * ?a +
    Base * Base ^ nat ?l * a a_last"
    by (simp add: ring_distribs)
  also from `a_first < a_last` `0 \<le> ?a`
    [[fact "?a \<le> _", THEN zdiv_mono1, OF `0 < Base`]]
    [[fact "bounds _ _ _ _ a"]]
    `a__index__subtype__1__first \<le> a_last - 1`
    `a_last \<le> a__index__subtype__1__last`
  have "\<dots> =
    num_of_big_int a a_first ?l + Base ^ nat ?l *
      (?a mod Base + Base *
       ((a a_last + ?a div Base) mod Base + Base * ?carry))"
    by (simp add: add_carry ring_distribs)
  also from `a_first < a_last`
  have "\<dots> =
    num_of_big_int
     (a(a_last - 1 := ?a mod Base,
        a_last := (a a_last + ?a div Base) mod Base))
     a_first (?l + (1 + 1)) +
    Base ^ nat (?l + 2) * ?carry"
    by (simp only: num_of_lint_sum nat_add_distrib)
      (simp add: ring_distribs)
  finally show ?thesis using [[fact "types__shr _ _ = _"]]
    [[fact "bounds _ _ _ _ a"]] [[fact "bounds _ _ _ _ b"]]
    `a_first < a_last` `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
    `b__index__subtype__1__first \<le> b_first + (a_last - a_first - 1)`
    `b_first + (a_last - a_first - 1) \<le> b__index__subtype__1__last`
    `0 \<le> c` `0 \<le> carry2`
    by (simp only: pow_simp_Base)
      (simp add: sdiv_pos_pos mult_nonneg_nonneg add_commute)
qed

spark_end

end
