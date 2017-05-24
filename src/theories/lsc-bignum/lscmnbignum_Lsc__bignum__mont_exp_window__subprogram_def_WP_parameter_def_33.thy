theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_33
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_33.xml"

why3_vc WP_parameter_def
proof -
  from
    `BV64.ult i ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `e_first \<le> e_last`
    `natural_in_range e_first`
    `natural_in_range e_last`
  have i: "int (nat \<lfloor>i\<rfloor>\<^sub>l) < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial BV64.ult_def
      uint_word_ariths word_of_int uint_word_of_int natural_in_range_def
      word64_to_int_def)

  from
    `bit_set e e_first i = True`
    `(bit_set e e_first i = True) = _`
    pos_mod_bound [of 32 "uint i"]
  show ?thesis
    by (simp add: num_of_lint_lower AND_div_mod [symmetric] mod_eq_1
      num_of_lint_AND_32 [OF i, unfolded word64_to_int_def] zdiv_int nat_mod_distrib
      uint_lt [where 'a=32, simplified]
      uint_div uint_mod word32_to_int_def word_uint_eq_iff uint_and uint_pow
      mod_pos_pos_trivial power_strict_increasing [of _ 32 2, simplified]
      unat_def uint_word_of_int word_of_int del: pos_mod_bound)
qed

why3_end

end
