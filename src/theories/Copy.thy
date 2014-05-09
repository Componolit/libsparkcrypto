theory Copy
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/copy"

spark_vc procedure_copy_3
  by simp

spark_vc procedure_copy_5
  using
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_copy_6
  using
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> _) \<and> (_ \<longrightarrow> _)`
    `a_first \<le> loop__1__i`
  by auto

spark_vc procedure_copy_8
  using `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> _) \<and> (_ \<longrightarrow> _)`
  by simp

spark_end

end
