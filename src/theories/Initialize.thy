theory Initialize
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/initialize.siv"

spark_vc procedure_initialize_4
  using H1
  by simp

spark_vc procedure_initialize_7
  using H1
  by simp

spark_end

end