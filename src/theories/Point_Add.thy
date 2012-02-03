theory Point_Add
imports Bignum
begin

lemma add_less_mod: "x < m \<Longrightarrow> y < m \<Longrightarrow>
  x + y - m * num_of_bool (b \<le> x + y) -
  m + m * num_of_bool (x + y - m * num_of_bool (b \<le> x + y) < m) < m"
  by (simp split add: num_of_bool_split)

lemma sub_less_mod: "x < m \<Longrightarrow> y < m \<Longrightarrow> 0 \<le> y \<Longrightarrow>
  x - y + m * num_of_bool (x < y) < m"
  by (simp split add: num_of_bool_split)


spark_open "$VCG_DIR/lsc_/ec/point_double.siv" (lsc__ec)

spark_vc procedure_point_double_17
  using
    `1 < num_of_big_int m _ _` 
    `num_of_big_int h1__8 _ _ = _`
    `num_of_big_int h3__10 _ _ = _`
    `num_of_big_int h1__12 _ _ = _`
    `num_of_big_int h1__11 _ _ = _`
  by (simp add: add_less_mod)

spark_vc procedure_point_double_21
  using `1 < num_of_big_int m _ _` `bounds _ _ _ _ h5__15`
  apply (simp only: `num_of_big_int h6__18 _ _ = _`)
  apply (rule sub_less_mod [THEN less_imp_le])
  apply (simp only: `num_of_big_int h6__17 _ _ = _`)
  apply (rule sub_less_mod)
  apply (simp add: `num_of_big_int h6__16 _ _ = _`)
  apply (simp_all add: `num_of_big_int h5__15 _ _ = _` num_of_lint_lower)
  done

spark_vc procedure_point_double_28
  using
    `\<forall>k. _ \<longrightarrow> x2__1 k = 0`
    `\<forall>k. _ \<longrightarrow> y2__2 k = 0`
    `\<forall>k. _ \<longrightarrow> z2__3 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_double_29
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int y2__24 _ _ = _`
    `num_of_big_int y2__21 _ _ = _`
    `num_of_big_int h1__23 _ _ = _`
  by (simp add: sub_less_mod)

spark_end


spark_open "$VCG_DIR/lsc_/ec/point_add.siv" (lsc__ec)

spark_vc procedure_point_add_23
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h5__11 _ _ = _`
    `num_of_big_int h1__7 _ _ = _`
    `num_of_big_int h2__8 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_27
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h6__12 _ _ = _`
    `num_of_big_int h3__9 _ _ = _`
    `num_of_big_int h4__10 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_30
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h3__25 _ _ = _`
    `num_of_big_int h3__24 _ _ = _`
    `num_of_big_int h2__21 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_36
proof -
  let "num_of_big_int _ ?i ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x2 k = x3__1 k`
  have "num_of_big_int x3__1 ?i ?k = num_of_big_int x2 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x2 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from `\<forall>k. _ \<longrightarrow> y2 k = y3__2 k`
  have "num_of_big_int y3__2 ?i ?k = num_of_big_int y2 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y2 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from `\<forall>k. _ \<longrightarrow> z2 k = z3__3 k`
  have "num_of_big_int z3__3 ?i ?k = num_of_big_int z2 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z2 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_37
proof -
  let "num_of_big_int _ ?i ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x1 k = x3__4 k`
  have "num_of_big_int x3__4 ?i ?k = num_of_big_int x1 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x1 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from `\<forall>k. _ \<longrightarrow> y1 k = y3__5 k`
  have "num_of_big_int y3__5 ?i ?k = num_of_big_int y1 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y1 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from `\<forall>k. _ \<longrightarrow> z1 k = z3__6 k`
  have "num_of_big_int z3__6 ?i ?k = num_of_big_int z1 ?i ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z1 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_39
  using
    `\<forall>k. _ \<longrightarrow> x3__14 k = 0`
    `\<forall>k. _ \<longrightarrow> y3__15 k = 0`
    `\<forall>k. _ \<longrightarrow> z3__16 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_add_40
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int y3__30 _ _ = _`
    `num_of_big_int h2__28 _ _ = _`
    `num_of_big_int h1__29 _ _ = _`
    `num_of_big_int z3__31 _ _ = _`
    `num_of_big_int h8__22 _ _ = _`
    `num_of_big_int h7__17 _ _ = _`
  by (simp_all add: sub_less_mod)

spark_end

end
