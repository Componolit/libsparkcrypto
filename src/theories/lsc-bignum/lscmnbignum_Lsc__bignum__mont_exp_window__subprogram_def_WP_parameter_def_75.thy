theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_75
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_75.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1)"

  from
    `natural_in_range e_first`
    `natural_in_range e_last`
    `BV64.ult i ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `e_first \<le> e_last`
    `_ \<longrightarrow> natural_in_range j2`
  have i: "uint i - j2 < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial BV64.ult_def
      natural_in_range_def uint_word_ariths word_of_int uint_word_of_int)

  from `s2 < j2`
  have "(2::int) ^ nat (j2 - s2) = 2 ^ nat (j2 - s2 - 1) * 2 ^ 1"
    by (simp only: power_add [symmetric]) (simp del: power.simps)
  then have "uint w * 2 ^ nat (j2 - s2) = uint w * 2 ^ nat (j2 - s2 - 1) * 2"
    by simp
  also note `(math_int_from_word w * _ ^ nat (j2 - s2 - 1) =
    num_of_big_int' e _ _ div _ mod _) = _` [simplified]
  also from `BV64.ule (of_int j2) i` `_ \<longrightarrow> natural_in_range j2`
  have "?e div 2 ^ nat (uint i - (j2 - 1)) mod 2 ^ nat j2 * 2 =
    (?e div 2 ^ nat (uint i - j2) div 2 * 2) mod (2 ^ nat (j2 + 1))"
    by (simp add:
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute
      num_of_lint_lower
      BV64.ule_def word_of_int uint_word_of_int
      natural_in_range_def mod_pos_pos_trivial)
  also from i `BV64.ule (of_int j2) i`
    `bit_set e e_first (i - of_int j2) \<noteq> _`
    `(bit_set e e_first (i - of_int j2) = _) = _`
    word64_to_int_upper [of i]
    `_ \<longrightarrow> natural_in_range j2`
    pos_mod_bound [of 32 "uint i - j2"]
  have "?e AND 2 ^ nat (uint i - j2) = 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      mod_pos_pos_trivial
      uint_lt [where 'a=32, simplified] uint_word_ariths uint_mod uint_div
      word_of_int uint_word_of_int natural_in_range_def
      BV64.ule_def word32_to_int_def word_uint_eq_iff uint_and uint_pow
      word64_to_int_def power_strict_increasing [of _ 32 2, simplified]
      unat_def del: num_of_lint_sum pos_mod_bound)
  then have "?e div 2 ^ nat (uint i - j2) div 2 * 2 =
    ?e div 2 ^ nat (uint i - j2) div 2 * 2 + ?e div 2 ^ nat (uint i - j2) mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    by simp
qed

why3_end

end
