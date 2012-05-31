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

spark_vc procedure_point_double_18
  using
    `1 < num_of_big_int m _ _` 
    `num_of_big_int h1__8 _ _ = _`
    `num_of_big_int h3__10 _ _ = _`
    `num_of_big_int h1__12 _ _ = _`
    `num_of_big_int h1__11 _ _ = _`
  by (simp add: add_less_mod)

spark_vc procedure_point_double_22
  using `1 < num_of_big_int m _ _` `bounds _ _ _ _ h5__15`
  apply (simp only: `num_of_big_int h6__18 _ _ = _`)
  apply (rule sub_less_mod [THEN less_imp_le])
  apply (simp only: `num_of_big_int h6__17 _ _ = _`)
  apply (rule sub_less_mod)
  apply (simp add: `num_of_big_int h6__16 _ _ = _`)
  apply (simp_all add: `num_of_big_int h5__15 _ _ = _` num_of_lint_lower)
  done

spark_vc procedure_point_double_26
proof -
  let "?l \<le> ?r" = ?thesis
  from
    `num_of_big_int h1__23 _ _ = _`
    `1 < num_of_big_int m _ _`
  have "?l < ?r" by (simp add: sign_simps)
  then show ?thesis by simp
qed

spark_vc procedure_point_double_29
  using
    `\<forall>k. _ \<longrightarrow> x2__1 k = 0`
    `\<forall>k. _ \<longrightarrow> y2__2 k = 0`
    `\<forall>k. _ \<longrightarrow> z2__3 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_double_30
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int y2__24 _ _ = _`
    `num_of_big_int y2__21 _ _ = _`
    `num_of_big_int h1__23 _ _ = _`
    `num_of_big_int x2__19 _ _ = _`
    `num_of_big_int z2__26 _ _ = _`
  by (simp_all add: sub_less_mod)

spark_end


spark_open "$VCG_DIR/lsc_/ec/point_add.siv" (lsc__ec)

spark_vc procedure_point_add_24
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h5__11 _ _ = _`
    `num_of_big_int h1__7 _ _ = _`
    `num_of_big_int h2__8 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_28
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h6__12 _ _ = _`
    `num_of_big_int h3__9 _ _ = _`
    `num_of_big_int h4__10 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_31
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h3__25 _ _ = _`
    `num_of_big_int h3__24 _ _ = _`
    `num_of_big_int h2__21 _ _ = _`
  by (simp add: sub_less_mod uminus_add_conv_diff add_commute)

spark_vc procedure_point_add_32
proof -
  let "?l \<le> ?r" = ?thesis
  from
    `num_of_big_int h3__25 _ _ < num_of_big_int m _ _`
    `1 < num_of_big_int m _ _`
  have "?l < ?r" by (simp add: sign_simps)
  then show ?thesis by simp
qed

spark_vc procedure_point_add_35
proof -
  let "?l \<le> ?r" = ?thesis
  from
    `num_of_big_int h1__29 _ _ = _`
    `1 < num_of_big_int m _ _`
  have "?l < ?r" by (simp add: sign_simps)
  then show ?thesis by simp
qed

spark_vc procedure_point_add_37
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x2 _ = x3__1 _`
  have "num_of_big_int x3__1 x3_first ?k = num_of_big_int x2 x2_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x2 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from `\<forall>k. _ \<longrightarrow> y2 _ = y3__2 _`
  have "num_of_big_int y3__2 y3_first ?k = num_of_big_int y2 y2_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y2 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from `\<forall>k. _ \<longrightarrow> z2 _ = z3__3 _`
  have "num_of_big_int z3__3 z3_first ?k = num_of_big_int z2 z2_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z2 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_38
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from `\<forall>k. _ \<longrightarrow> x1 _ = x3__4 _`
  have "num_of_big_int x3__4 x3_first ?k = num_of_big_int x1 x1_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int x1 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from `\<forall>k. _ \<longrightarrow> y1 _ = y3__5 _`
  have "num_of_big_int y3__5 y3_first ?k = num_of_big_int y1 y1_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int y1 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from `\<forall>k. _ \<longrightarrow> z1 _ = z3__6 _`
  have "num_of_big_int z3__6 z3_first ?k = num_of_big_int z1 z1_first ?k"
    by (simp add: num_of_lint_ext)
  with `num_of_big_int z1 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_40
  using
    `\<forall>k. _ \<longrightarrow> x3__14 k = 0`
    `\<forall>k. _ \<longrightarrow> y3__15 k = 0`
    `\<forall>k. _ \<longrightarrow> z3__16 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_add_41
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int y3__30 _ _ = _`
    `num_of_big_int h2__28 _ _ = _`
    `num_of_big_int h1__29 _ _ = _`
    `num_of_big_int z3__31 _ _ = _`
    `num_of_big_int h8__22 _ _ = _`
    `num_of_big_int h7__17 _ _ = _`
    `num_of_big_int x3__26 _ _ = _`
  by (simp_all add: sub_less_mod)

spark_end

end
