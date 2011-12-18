theory Single_Add_Mult_Mult
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/bignum/single_add_mult_mult.siv"

spark_vc procedure_single_add_mult_mult_11
proof -
  let ?f = "\<lambda>b. (((carry2 + lsc__types__shr (v * w) 32) mod b +
      lsc__types__shr (x * y) 32) mod b +
    lsc__types__shr (a + carry1 + v * w mod Base + x * y mod Base) 32) mod b"
  have "0 < Base" by simp
  from
    `lsc__types__shr (?f _) 32 = _`
    `0 \<le> ?f _`
    `?f _ \<le> _` [THEN zdiv_mono1, OF `0 < Base`]
  show ?thesis
    by (simp add: sdiv_pos_pos)
qed

spark_vc procedure_single_add_mult_mult_12
proof -
  from `a \<le> _` `carry1 \<le> _`
  have "(a + carry1 + v * w mod Base + x * y mod Base) div Base < 4"
    by simp
  then have "carry2 + v * w div Base + x * y div Base +
    (a + carry1 + v * w mod Base + x * y mod Base) div Base < 3 * Base"
  using
    zdiv_mono1
      [OF mult_mono [OF `v \<le> _` `w \<le> _` _ `0 \<le> w`], of Base]
    zdiv_mono1
      [OF mult_mono [OF `x \<le> _` `y \<le> _` _ `0 \<le> y`], of Base]
    `carry2 \<le> _`
    by simp
  with
    `lsc__types__shr (v * w) 32 = _`
    `lsc__types__shr (x * y) 32 = _`
    `lsc__types__shr (_ + _ mod _) 32 = _`
    `lsc__types__shr (_ mod _) 32 = _`
    `0 \<le> v` `0 \<le> w` `0 \<le> x` `0 \<le> y` `0 \<le> a` `0 \<le> carry1` `0 \<le> carry2`
  show ?thesis
    using [[simproc del: pull_mod]]
    by (simp add: mult_nonneg_nonneg sdiv_pos_pos pull_mods
      mod_pos_pos_trivial mult_nonneg_nonneg pos_imp_zdiv_nonneg_iff
      ring_distribs add_ac)
qed

spark_end

end
