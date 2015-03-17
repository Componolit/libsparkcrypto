theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_18
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_18.xml"

why3_vc WP_parameter_def
proof -
  from `1 \<le> h` natural_to_int_lower [of l]
  have "0 \<le> (h - 1) * (\<lfloor>l\<rfloor>\<^sub>\<nat> + 1)" by simp
  with `\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat>`
  show ?thesis by (simp add: mk_bounds_fst)
qed

why3_end

end
