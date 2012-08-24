theory Uncompress_Point
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec/uncompress_point.siv" (lsc__ec)

spark_vc procedure_uncompress_point_7
  using
    `x_first < x_last`
    `1 < num_of_big_int m m_first (x_last - x_first + 1)`
  by (simp add: num_of_lint_all0)

spark_vc procedure_uncompress_point_21
  using
    `\<forall>k. 0 \<le> k \<and> k \<le> x_last - x_first \<longrightarrow> h3__9 k = y__10 (y_first + k)`
    `num_of_big_int h3__9 _ _ = _`
    `1 < num_of_big_int m m_first (x_last - x_first + 1)`
    num_of_lint_ext [of y_first _ y__10 h3__9 0]
  by simp

spark_vc procedure_uncompress_point_22
proof -
  from
    `num_of_big_int h3__9 0 (x_last - x_first + 1) = _`
    `1 < num_of_big_int m m_first (x_last - x_first + 1)`
  have "num_of_big_int h3__9 0 (x_last - x_first + 1) <
    num_of_big_int m m_first (x_last - x_first + 1)"
    by simp
  moreover from
    `bounds _ _ _ _ y__11`
    `y__index__subtype__1__first \<le> y_first`
    `y_first + (x_last - x_first) \<le> y__index__subtype__1__last`
  have "num_of_big_int y__11 y_first (x_last - x_first + 1) <
    Base ^ nat (x_last - x_first + 1)"
    by (simp add: num_of_lint_upper)
  moreover from
    `bounds _ _ _ _ h3__9`
    `x_last - x_first < _`
  have "0 \<le> num_of_big_int h3__9 0 (x_last - x_first + 1)"
    by (simp add: num_of_lint_lower)
  ultimately show ?thesis
    using
      `num_of_big_int m _ _ - num_of_big_int h3__9 _ _ = _`
      `num_of_big_int h3__9 _ _ = _`
      `num_of_big_int h3__9 0 (x_last - x_first + 1) \<noteq> 0`
    by (cases carry__11) simp_all
qed

spark_end

end
