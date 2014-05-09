theory Native_To_BE
imports SPARK
begin

spark_open "$VCG_DIR/lsc_/bignum/native_to_be" (lsc__bignum)

spark_vc procedure_native_to_be_5
  using
    `b__index__subtype__1__first \<le> b_first`
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_end

end
