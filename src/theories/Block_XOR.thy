theory Block_XOR
imports SPARK
begin

spark_open "$VCG_DIR/lsc_/ops32/block_xor"

spark_vc procedure_block_xor_10
  using `\<forall>pos. _ \<and> _ \<and> _ \<and> _ \<longrightarrow> result pos = xor2 (left pos) (right pos)`
  by auto

spark_vc procedure_block_xor_11
  using
    `result__index__subtype__1__first \<le> result__index__subtype__1__last`
    `result__index__subtype__1__last < result__index__subtype__1__first`
  by auto

spark_end


spark_open "$VCG_DIR/lsc_/ops64/block_xor"

spark_vc procedure_block_xor_10
  using `\<forall>pos. _ \<and> _ \<and> _ \<and> _ \<longrightarrow> result pos = xor2 (left pos) (right pos)`
  by auto

spark_vc procedure_block_xor_11
  using
    `result__index__subtype__1__first \<le> result__index__subtype__1__last`
    `result__index__subtype__1__last < result__index__subtype__1__first`
  by auto

spark_end

end
