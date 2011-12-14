theory Copy
imports Bignum
begin

spark_open "$VCG_DIR/copy.siv"

spark_vc procedure_copy_4
  using `\<forall>k. a_first \<le> k \<and> k \<le> loop__1__i - 1 \<longrightarrow>
    a k = b (b_first + (k - a_first))`
  by simp

spark_vc procedure_copy_5
  using
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_copy_7
  using `\<forall>k. a_first \<le> k \<and> k \<le> a_last - 1 \<longrightarrow>
    a k = b (b_first + (k - a_first))`
  by simp

spark_end

end
