theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `a_first < a_last` `natural_in_range aux4_first`
  have "0 < aux4_first + (a_last - a_first)"
    by (simp add: natural_in_range_def)
  moreover have "(2::int) ^ 0 \<le> 2 ^ nat k" by (simp add: power_increasing)
  with `a_first < a_last`
  have "2 ^ 0 * (a_last - a_first + 1) \<le> 2 ^ nat k * (a_last - a_first + 1)"
    by (simp add: mult_right_mono)
  with
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
    integer_to_int_upper [of aux4__last]
  have "aux4_first + (a_last - a_first) \<le> 2147483647"
    by simp
  ultimately show ?thesis
    by (simp add: integer_in_range_def)
qed

why3_end

end
