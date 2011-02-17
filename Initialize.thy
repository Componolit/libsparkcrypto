theory Initialize
imports Bignum
begin

spark_open "out/bignum/initialize.siv"

spark_vc procedure_initialize_4
  using H1
  by simp

spark_vc procedure_initialize_7
  using H1
  by simp

spark_end

end
