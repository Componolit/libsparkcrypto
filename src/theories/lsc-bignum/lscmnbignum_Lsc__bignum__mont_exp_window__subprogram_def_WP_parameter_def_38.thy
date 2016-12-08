theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_38
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_38.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1)"

  have "?e div 2 ^ nat (uint i1 - (j2 - 1)) mod 2 ^ nat j2 < 2 ^ nat j2"
    by simp
  also from `j2 \<le> k` `k \<le> 30`
  have "nat j2 \<le> 30" by simp
  then have "(2::int) ^ nat j2 \<le> 2 ^ 30"
    by (rule power_increasing) simp
  finally have e: "?e div 2 ^ nat (uint i1 - (j2 - 1)) mod 2 ^ nat j2 * 2 < Base"
    by simp

  from
    `natural_in_range e_first`
    `natural_in_range e_last`
    `BV64.ult i1 ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `e_first \<le> e_last`
    `_ \<longrightarrow> natural_in_range j2`
  have i: "uint i1 - j2 < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial BV64.ult_def
      natural_in_range_def uint_word_ariths word_of_int uint_word_of_int)

  from `s2 < j2`
  have "(2::int) ^ nat (j2 - s2) = 2 ^ nat (j2 - s2 - 1) * 2 ^ 1"
    by (simp only: power_add [symmetric]) (simp del: power.simps)
  then have "uint w * ((2::int) ^ nat (j2 - s2)) mod Base OR 1 =
    uint w * (2 ^ nat (j2 - s2 - 1) * 2 ^ 1) mod Base OR 1"
    by simp
  also from
    `(math_int_from_word w * math_int_from_word (of_int 2) ^ nat (j2 - s2 - 1) = _) = _`
  have "uint w * (2 ^ nat (j2 - s2 - 1) * 2 ^ 1) =
    ?e div 2 ^ nat (uint i1 - (j2 - 1)) mod 2 ^ nat j2 * 2"
    by (simp add: num_of_lint_lower)
  also from e have "\<dots> mod Base OR 1 =
    ?e div 2 ^ nat (uint i1 - (j2 - 1)) mod 2 ^ nat j2 * 2 + 1"
    by (simp add: mod_pos_pos_trivial OR_plus1)
  also from `BV64.ule (of_int j2) i1`
    `_ \<longrightarrow> natural_in_range j2`
  have "\<dots> =
    (?e div 2 ^ nat (uint i1 - j2) div 2 * 2 + 1) mod (2 ^ nat (j2 + 1))"
    by (simp add: natural_to_int_lower mod_mult_add
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute [of 2]
      BV64.ule_def word_of_int uint_word_of_int natural_in_range_def
      mod_pos_pos_trivial)
  also from i `BV64.ule (of_int j2) i1`
    `_ = (elts e (e_first + uint ((i1 - of_int j2) div of_int 32)) AND
     of_int 2 ^ nat (uint ((i1 - of_int j2) mod of_int 32)) \<noteq> of_int 0)`
    `bit_set e e_first (i1 - of_int j2) = _`
    uint_lt [of i1]
    `_ \<longrightarrow> natural_in_range j2`
  have "?e AND 2 ^ nat (uint i1 - j2) \<noteq> 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      mod_pos_pos_trivial
      uint_lt [where 'a=32, simplified]
      BV64.ule_def word_of_int uint_word_of_int natural_in_range_def
      uint_div uint_mod uint_word_ariths
      word32_to_int_def word_uint_eq_iff uint_and uint_pow
      power_strict_increasing [of _ 32 2, simplified]
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (uint i1 - j2) div 2 * 2 + 1 =
    ?e div 2 ^ nat (uint i1 - j2) div 2 * 2 + ?e div 2 ^ nat (uint i1 - j2) mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using
      `s2 < j2`
      `_ \<longrightarrow> natural_in_range j2`
      `_ \<longrightarrow> natural_in_range s2`
    by (simp add: uint_or BV32.facts.to_uint_lsl emod_def uint_word_ariths
      word_of_int uint_word_of_int natural_in_range_def
      mod_pos_pos_trivial)
qed

why3_end

end
