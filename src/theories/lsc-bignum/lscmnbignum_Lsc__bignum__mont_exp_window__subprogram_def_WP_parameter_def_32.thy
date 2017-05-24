theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_32
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_32.xml"

why3_vc WP_parameter_def
  using
    `BV64.ult i ((of_int (e_last - e_first) + of_int 1) * of_int 32)`
    `e_first \<le> e_last`
    `e_last \<le> \<lfloor>snd (rt e)\<rfloor>\<^sub>\<int>`
    `natural_in_range e_first`
    `natural_in_range e_last`
    integer_to_int_upper [of "snd (rt e)"]
  by (simp add: mod_pos_pos_trivial BV64.ult_def BV64.ule_def
    uint_word_ariths uint_div word_of_int uint_word_of_int natural_in_range_def)

why3_end

end
