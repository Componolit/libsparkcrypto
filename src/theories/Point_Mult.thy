theory Point_Mult
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec/point_mult.siv" (lsc__ec)

spark_vc procedure_point_mult_6
  using
    `\<forall>k. _ \<longrightarrow> x2__1 k = 0`
    `\<forall>k. _ \<longrightarrow> y2__2 k = 0`
    `\<forall>k. _ \<longrightarrow> z2__3 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_mult_20
proof -
  let "num_of_big_int _ ?i ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x3__4 k = x2__6 k`
  have "num_of_big_int x2__6 ?i ?k = num_of_big_int x3__4 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x3__4 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from `\<forall>k. _ \<longrightarrow> y3__4 k = y2__7 k`
  have "num_of_big_int y2__7 ?i ?k = num_of_big_int y3__4 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y3__4 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from `\<forall>k. _ \<longrightarrow> z3__4 k = z2__8 k`
  have "num_of_big_int z2__8 ?i ?k = num_of_big_int z3__4 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z3__4 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_end

end
