theory Point_Mult
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec/point_mult.siv" (lsc__ec)

spark_vc procedure_point_mult_7
  using
    `\<forall>k. _ \<longrightarrow> x2__1 k = 0`
    `\<forall>k. _ \<longrightarrow> y2__2 k = 0`
    `\<forall>k. _ \<longrightarrow> z2__3 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_mult_21
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x3__4 _ = x2__6 _`
  have "num_of_big_int x2__6 x2_first ?k = num_of_big_int x3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x3__4 _ _ < num_of_big_int m _ _`
  show ?C1 by (simp add: add_commute)

  from `\<forall>k. _ \<longrightarrow> y3__4 _ = y2__7 _`
  have "num_of_big_int y2__7 y2_first ?k = num_of_big_int y3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y3__4 _ _ < num_of_big_int m _ _`
  show ?C2 by (simp add: add_commute)

  from `\<forall>k. _ \<longrightarrow> z3__4 _ = z2__8 _`
  have "num_of_big_int z2__8 z2_first ?k = num_of_big_int z3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z3__4 _ _ < num_of_big_int m _ _`
  show ?C3 by (simp add: add_commute)
qed

spark_end


spark_open "$VCG_DIR/lsc_/ec/two_point_mult.siv" (lsc__ec)

spark_vc procedure_two_point_mult_8
  using
    `\<forall>k. _ \<longrightarrow> x3__2 k = 0`
    `\<forall>k. _ \<longrightarrow> y3__3 k = 0`
    `\<forall>k. _ \<longrightarrow> z3__4 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_two_point_mult_17
  using
    `e1_first \<le> loop__1__i`
    `loop__1__i \<le> e1_last`
    `e2__index__subtype__1__first \<le> e2_first`
    `e2_first + (e1_last - e1_first) \<le> e2__index__subtype__1__last`
    `e2__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_two_point_mult_20
  using
    `e1_first \<le> loop__1__i`
    `loop__1__i \<le> e1_last`
    `e2__index__subtype__1__first \<le> e2_first`
    `e2_first + (e1_last - e1_first) \<le> e2__index__subtype__1__last`
    `e2__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_two_point_mult_28
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x4__5 _ = x3__9 _`
  have "num_of_big_int x3__9 x3_first ?k = num_of_big_int x4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x4__5 _ _ < num_of_big_int m _ _`
  show ?C1 by (simp add: add_commute)

  from `\<forall>k. _ \<longrightarrow> y4__5 _ = y3__10 _`
  have "num_of_big_int y3__10 y3_first ?k = num_of_big_int y4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y4__5 _ _ < num_of_big_int m _ _`
  show ?C2 by (simp add: add_commute)

  from `\<forall>k. _ \<longrightarrow> z4__5 _ = z3__11 _`
  have "num_of_big_int z3__11 z3_first ?k = num_of_big_int z4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z4__5 _ _ < num_of_big_int m _ _`
  show ?C3 by (simp add: add_commute)
qed

spark_end

end
