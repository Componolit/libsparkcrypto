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


spark_open "$VCG_DIR/lsc_/ec/point_double" (lsc__ec)

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


spark_open "$VCG_DIR/lsc_/ec/point_add" (lsc__ec)

spark_vc procedure_point_add_30
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h5__17 _ _ = _`
    `num_of_big_int h1__13 _ _ = _`
    `num_of_big_int h2__14 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_34
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h6__18 _ _ = _`
    `num_of_big_int h3__15 _ _ = _`
    `num_of_big_int h4__16 _ _ = _`
  by (simp add: sub_less_mod)

spark_vc procedure_point_add_37
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int h3__31 _ _ = _`
    `num_of_big_int h3__30 _ _ = _`
    `num_of_big_int h2__27 _ _ = _`
  by (simp add: sub_less_mod uminus_add_conv_diff add_commute)

spark_vc procedure_point_add_38
proof -
  let "?l \<le> ?r" = ?thesis
  from
    `num_of_big_int h3__31 _ _ < num_of_big_int m _ _`
    `1 < num_of_big_int m _ _`
  have "?l < ?r" by (simp add: sign_simps)
  then show ?thesis by simp
qed

spark_vc procedure_point_add_41
proof -
  let "?l \<le> ?r" = ?thesis
  from
    `num_of_big_int h1__35 _ _ = _`
    `1 < num_of_big_int m _ _`
  have "?l < ?r" by (simp add: sign_simps)
  then show ?thesis by simp
qed

spark_vc procedure_point_add_43
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> x3__4 _ = x2 _) \<and> _`
    `x3__index__subtype__1__first \<le> x3_first`
    `x3_first + (x1_last - x1_first) \<le> x3__index__subtype__1__last`
  have "num_of_big_int x3__4 x3_first ?k = num_of_big_int x2 x2_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int x2 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> y3__5 _ = y2 _) \<and> _`
    `y3__index__subtype__1__first \<le> y3_first`
    `y3_first + (x1_last - x1_first) \<le> y3__index__subtype__1__last`
  have "num_of_big_int y3__5 y3_first ?k = num_of_big_int y2 y2_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int y2 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> z3__6 _ = z2 _) \<and> _`
    `z3__index__subtype__1__first \<le> z3_first`
    `z3_first + (x1_last - x1_first) \<le> z3__index__subtype__1__last`
  have "num_of_big_int z3__6 z3_first ?k = num_of_big_int z2 z2_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int z2 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_44
proof -
  let "num_of_big_int _ _ ?k < _" = ?C1

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> x3__10 _ = x1 _) \<and> _`
    `x3__index__subtype__1__first \<le> x3_first`
    `x3_first + (x1_last - x1_first) \<le> x3__index__subtype__1__last`
  have "num_of_big_int x3__10 x3_first ?k = num_of_big_int x1 x1_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int x1 _ _ < num_of_big_int m _ _`
  show ?C1 by simp

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> y3__11 _ = y1 _) \<and> _`
    `y3__index__subtype__1__first \<le> y3_first`
    `y3_first + (x1_last - x1_first) \<le> y3__index__subtype__1__last`
  have "num_of_big_int y3__11 y3_first ?k = num_of_big_int y1 y1_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int y1 _ _ < num_of_big_int m _ _`
  show ?C2 by simp

  from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> z3__12 _ = z1 _) \<and> _`
    `z3__index__subtype__1__first \<le> z3_first`
    `z3_first + (x1_last - x1_first) \<le> z3__index__subtype__1__last`
  have "num_of_big_int z3__12 z3_first ?k = num_of_big_int z1 z1_first ?k"
    by (simp add: num_of_lint_ext sign_simps)
  with `num_of_big_int z1 _ _ < num_of_big_int m _ _`
  show ?C3 by simp
qed

spark_vc procedure_point_add_46
  using
    `\<forall>k. _ \<longrightarrow> x3__20 k = 0`
    `\<forall>k. _ \<longrightarrow> y3__21 k = 0`
    `\<forall>k. _ \<longrightarrow> z3__22 k = 0`
    `1 < num_of_big_int m _ _`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_point_add_47
  using
    `1 < num_of_big_int m _ _`
    `num_of_big_int y3__36 _ _ = _`
    `num_of_big_int h2__34 _ _ = _`
    `num_of_big_int h1__35 _ _ = _`
    `num_of_big_int z3__37 _ _ = _`
    `num_of_big_int h8__28 _ _ = _`
    `num_of_big_int h7__23 _ _ = _`
    `num_of_big_int x3__32 _ _ = _`
  by (simp_all add: sub_less_mod)

spark_end

end
