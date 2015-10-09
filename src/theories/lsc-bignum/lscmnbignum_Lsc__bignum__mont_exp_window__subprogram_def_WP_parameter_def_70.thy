theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `\<not> BV64.ult result3 (of_int s2)`
    `BV64.ult result3 ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `0 \<le> s2` `s2 \<le> n_last ()`
  by (simp add: uint_word_ariths BV64.ult_def mod_pos_pos_trivial
    word_of_int uint_word_of_int n_last_def)

why3_end

end
