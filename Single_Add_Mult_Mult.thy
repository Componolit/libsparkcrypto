theory Single_Add_Mult_Mult
imports Bignum
begin

spark_open "$VCG_DIR/single_add_mult_mult.siv"

spark_vc procedure_single_add_mult_mult_11
proof -
  let ?f = "\<lambda>b. (((carry2 + types__shr (v * w) 32) mod b +
      types__shr (x * y) 32) mod b +
    types__shr (a + carry1 + v * w mod Base + x * y mod Base) 32) mod b"
  have "0 < Base" by simp
  from
    [[fact "types__shr (?f _) 32 = _"]]
    [[fact "0 \<le> ?f _"]]
    [[fact "?f _ \<le> _", THEN zdiv_mono1, OF `0 < Base`]]
  show ?thesis
    by (simp add: sdiv_pos_pos)
qed

spark_vc procedure_single_add_mult_mult_12
proof -
  from [[fact "a \<le> _"]] [[fact "carry1 \<le> _ "]]
  have "(a + carry1 + v * w mod Base + x * y mod Base) div Base < 4"
    by simp
  then have "carry2 + v * w div Base + x * y div Base +
    (a + carry1 + v * w mod Base + x * y mod Base) div Base < 3 * Base"
  using
    zdiv_mono1
      [OF mult_mono [OF [[fact "v \<le> _"]] [[fact "w \<le> _"]] _ `0 \<le> w`], of Base]
    zdiv_mono1
      [OF mult_mono [OF [[fact "x \<le> _"]] [[fact "y \<le> _"]] _ `0 \<le> y`], of Base]
    [[fact "carry2 \<le> _"]]
    by simp
  with
    [[fact "types__shr (v * w) 32 = _"]]
    [[fact "types__shr (x * y) 32 = _"]]
    [[fact "types__shr (_ + _ mod _) 32 = _"]]
    [[fact "types__shr (_ mod _) 32 = _"]]
    `0 \<le> v` `0 \<le> w` `0 \<le> x` `0 \<le> y` `0 \<le> a` `0 \<le> carry1` `0 \<le> carry2`
  show ?thesis
    using [[simproc del: pull_mod]]
    by (simp add: mult_nonneg_nonneg sdiv_pos_pos pull_mods
      mod_pos_pos_trivial mult_nonneg_nonneg pos_imp_zdiv_nonneg_iff
      ring_distribs add_ac)
qed

spark_end

end
