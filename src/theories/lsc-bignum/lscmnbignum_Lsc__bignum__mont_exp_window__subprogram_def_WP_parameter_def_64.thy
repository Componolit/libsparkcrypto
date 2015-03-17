theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_64
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_64.xml"

why3_vc WP_parameter_def
proof -
  have "0 \<le> \<lfloor>o10\<rfloor>\<^sub>\<nat> * (\<lfloor>l\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: natural_to_int_lower)
  with
    `\<lfloor>aux4_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux4_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  show ?thesis
    by (simp add: mk_bounds_fst)
qed

why3_end

end
