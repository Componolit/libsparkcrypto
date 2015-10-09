theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_56
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_56.xml"

why3_vc WP_parameter_def
  using `\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> aux4_first` `a_first < a_last`
  by (simp add: mk_bounds_fst add_increasing2)

why3_end

end
