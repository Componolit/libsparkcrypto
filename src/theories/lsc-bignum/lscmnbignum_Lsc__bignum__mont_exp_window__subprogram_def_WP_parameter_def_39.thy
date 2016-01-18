theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_39
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_39.xml"

why3_vc WP_parameter_def
  using `BV64.ule (of_int j2) i1` `_ \<longrightarrow> natural_in_range j2`
  by (simp add: BV64.ule_def
    word_of_int uint_word_of_int natural_in_range_def mod_pos_pos_trivial)

why3_end

end
