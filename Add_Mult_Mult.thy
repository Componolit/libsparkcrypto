theory Add_Mult_Mult
imports Bignum
begin

spark_open "out/bignum/add_mult_mult.siv"

spark_vc procedure_add_mult_mult_3
  by simp

spark_vc procedure_add_mult_mult_4
proof -
  note inv = [[fact "num_of_big_int a_init _ _ + num_of_big_int b _ _ * x +
    num_of_big_int c _ _ * y + carry1_init + Base * carry2_init = _"]]
  note single =
    [[fact "a _ + b _ * x + c _ * y + carry1 + Base * carry2 = _"]]
  from `a_first \<le> loop__1__i` `loop__1__i < a_last`
    `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last + 1 \<longrightarrow> a k = a_init k`
  have "num_of_big_int a_init (a_first + 1) (loop__1__i + 1 - a_first) +
    num_of_big_int b b_first (loop__1__i + 1 - a_first) * x +
    num_of_big_int c c_first (loop__1__i + 1 - a_first) * y +
    carry1_init + Base * carry2_init =
    num_of_big_int a_init (a_first + 1) (loop__1__i - a_first) +
    num_of_big_int b b_first (loop__1__i - a_first) * x +
    num_of_big_int c c_first (loop__1__i - a_first) * y +
    carry1_init + Base * carry2_init +
    Base ^ nat (loop__1__i - a_first) *
      (a (loop__1__i + 1) +
       b (b_first + (loop__1__i - a_first)) * x +
       c (c_first + (loop__1__i - a_first)) * y)"
    by (simp add: diff_add_eq [symmetric] ring_distribs)
      (simp add: add_commute)
  also note inv
  also have "num_of_big_int a a_first (loop__1__i - a_first) +
    Base ^ nat (loop__1__i - a_first) * (carry1 + Base * carry2) +
    Base ^ nat (loop__1__i - a_first) *
      (a (loop__1__i + 1) +
       b (b_first + (loop__1__i - a_first)) * x +
       c (c_first + (loop__1__i - a_first)) * y) =
    num_of_big_int a a_first (loop__1__i - a_first) +
    Base ^ nat (loop__1__i - a_first) *
      (a (loop__1__i + 1) +
       b (b_first + (loop__1__i - a_first)) * x +
       c (c_first + (loop__1__i - a_first)) * y +
       carry1 + Base * carry2)"
    by (simp add: ring_distribs)
  also note single
  finally show ?C1 using `a_first \<le> loop__1__i`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib ring_distribs)
next
  from `\<forall>k. loop__1__i \<le> k \<and> k \<le> a_last + 1 \<longrightarrow> a k = a_init k`
  show ?C2 by simp
qed

spark_vc procedure_add_mult_mult_6
  using
    [[fact "bounds _ _ _ _ c"]]
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
    `c__index__subtype__1__first \<le> c_first`
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    [[fact "bounds _ _ _ _ b"]]
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__first \<le> b_first`
    `c__index__subtype__1__last \<le> 2147483647`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_add_mult_mult_10
proof -
  note inv = [[fact "num_of_big_int a_init _ _ + num_of_big_int b _ _ * x +
    num_of_big_int c _ _ * y + carry1_init + Base * carry2_init = _"]]
  note single =
    [[fact "a _ + b _ * x + c _ * y + carry1 + Base * carry2 = _"]]
  from `a_first \<le> a_last`
    `\<forall>k. a_last \<le> k \<and> k \<le> a_last + 1 \<longrightarrow> a k = a_init k`
  have "num_of_big_int a_init (a_first + 1) (a_last - a_first + 1) +
    num_of_big_int b b_first (a_last - a_first + 1) * x +
    num_of_big_int c c_first (a_last - a_first + 1) * y +
    carry1_init + Base * carry2_init =
    num_of_big_int a_init (a_first + 1) (a_last - a_first) +
    num_of_big_int b b_first (a_last - a_first) * x +
    num_of_big_int c c_first (a_last - a_first) * y +
    carry1_init + Base * carry2_init +
    Base ^ nat (a_last - a_first) *
      (a (a_last + 1) +
       b (b_first + (a_last - a_first)) * x +
       c (c_first + (a_last - a_first)) * y)"
    by (simp add: ring_distribs) (simp add: add_commute)
  also note inv
  also have "num_of_big_int a a_first (a_last - a_first) +
    Base ^ nat (a_last - a_first) * (carry1 + Base * carry2) +
    Base ^ nat (a_last - a_first) *
      (a (a_last + 1) +
       b (b_first + (a_last - a_first)) * x +
       c (c_first + (a_last - a_first)) * y) =
    num_of_big_int a a_first (a_last - a_first) +
    Base ^ nat (a_last - a_first) *
      (a (a_last + 1) +
       b (b_first + (a_last - a_first)) * x +
       c (c_first + (a_last - a_first)) * y +
       carry1 + Base * carry2)"
    by (simp add: ring_distribs)
  also note single
  finally show ?C1 using `a_first \<le> a_last`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib ring_distribs)
qed

spark_end

end
