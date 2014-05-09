theory Point_Mult
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec/point_mult" (lsc__ec)

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

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> x2__6 _ = x3__4 _) \<and> _`
    `x2__index__subtype__1__first \<le> x2_first`
    `x2_first + (x1_last - x1_first) \<le> x2__index__subtype__1__last`
  have "num_of_big_int x2__6 x2_first ?k = num_of_big_int x3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x3__4 _ _ < num_of_big_int m _ _`
  show ?C1 by (simp add: add_commute)

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> y2__7 _ = y3__4 _) \<and> _`
    `y2__index__subtype__1__first \<le> y2_first`
    `y2_first + (x1_last - x1_first) \<le> y2__index__subtype__1__last`
  have "num_of_big_int y2__7 y2_first ?k = num_of_big_int y3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y3__4 _ _ < num_of_big_int m _ _`
  show ?C2 by (simp add: add_commute)

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> z2__8 _ = z3__4 _) \<and> _`
    `z2__index__subtype__1__first \<le> z2_first`
    `z2_first + (x1_last - x1_first) \<le> z2__index__subtype__1__last`
  have "num_of_big_int z2__8 z2_first ?k = num_of_big_int z3__4 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z3__4 _ _ < num_of_big_int m _ _`
  show ?C3 by (simp add: add_commute)
qed

spark_end


spark_open "$VCG_DIR/lsc_/ec/two_point_mult" (lsc__ec)

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

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> x3__9 _ = x4__5 _) \<and> _`
    `x3__index__subtype__1__first \<le> x3_first`
    `x3_first + (x1_last - x1_first) \<le> x3__index__subtype__1__last`
  have "num_of_big_int x3__9 x3_first ?k = num_of_big_int x4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x4__5 _ _ < num_of_big_int m _ _`
  show ?C1 by (simp add: add_commute)

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> y3__10 _ = y4__5 _) \<and> _`
    `y3__index__subtype__1__first \<le> y3_first`
    `y3_first + (x1_last - x1_first) \<le> y3__index__subtype__1__last`
  have "num_of_big_int y3__10 y3_first ?k = num_of_big_int y4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y4__5 _ _ < num_of_big_int m _ _`
  show ?C2 by (simp add: add_commute)

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> z3__11 _ = z4__5 _) \<and> _`
    `z3__index__subtype__1__first \<le> z3_first`
    `z3_first + (x1_last - x1_first) \<le> z3__index__subtype__1__last`
  have "num_of_big_int z3__11 z3_first ?k = num_of_big_int z4__5 0 ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z4__5 _ _ < num_of_big_int m _ _`
  show ?C3 by (simp add: add_commute)
qed

spark_end

end
