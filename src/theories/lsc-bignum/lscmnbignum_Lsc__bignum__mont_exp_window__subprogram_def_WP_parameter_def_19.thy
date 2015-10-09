theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_19
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_19.xml"

why3_vc WP_parameter_def
proof -
  from `1 \<le> h1` `a_first < a_last`
  have "0 \<le> (h1 - 1) * (a_last - a_first + 1)" by simp
  with `\<lfloor>aux4__first\<rfloor>\<^sub>\<int> \<le> aux4_first` `a_first < a_last`
  show ?thesis by (simp add: mk_bounds_fst)
qed

why3_end

end
