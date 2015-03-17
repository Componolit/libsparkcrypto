theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
proof -
  have "(2::int) ^ 0 \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>" by (simp add: power_increasing)
  with `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "2 ^ 0 * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: mult_right_mono)
  with
    `\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) - 1) \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  show ?thesis by (simp add: mk_bounds_snd)
qed

why3_end

end
