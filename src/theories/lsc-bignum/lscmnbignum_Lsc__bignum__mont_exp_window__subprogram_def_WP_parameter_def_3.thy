theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  have "(2::int) ^ 0 \<le> 2 ^ nat k" by (simp add: power_increasing)
  with `a_first < a_last`
  have "2 ^ 0 * (a_last - a_first + 1) \<le> 2 ^ nat k * (a_last - a_first + 1)"
    by (simp add: mult_right_mono)
  with
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
  show ?thesis by simp
qed

why3_end

end
