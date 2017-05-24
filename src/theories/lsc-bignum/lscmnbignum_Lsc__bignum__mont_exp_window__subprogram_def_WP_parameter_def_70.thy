theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70.xml"

why3_vc WP_parameter_def
  using
    `\<not> BV64.ult i (of_int s1)`
    `BV64.ult i ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `_ \<longrightarrow> natural_in_range s1`
  by (auto simp add: uint_word_ariths BV64.ult_def mod_pos_pos_trivial
    word_of_int uint_word_of_int natural_in_range_def)

why3_end

end
