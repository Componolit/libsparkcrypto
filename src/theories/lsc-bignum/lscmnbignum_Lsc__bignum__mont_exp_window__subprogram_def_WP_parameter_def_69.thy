theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_69
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_69.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `\<not> BV64.ult i1 (of_int s2)`
    uint_lt [of i1]
    `_ \<longrightarrow> natural_in_range s2`
  by (simp add: uint_word_ariths BV64.ult_def mod_pos_pos_trivial
    word_of_int uint_word_of_int natural_in_range_def)

why3_end

end
