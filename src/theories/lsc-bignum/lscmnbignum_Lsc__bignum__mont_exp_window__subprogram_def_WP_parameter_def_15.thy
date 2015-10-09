theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_15
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_15.xml"

why3_vc WP_parameter_def
proof -
  from `1 \<le> h1` `a_first < a_last`
  have "0 \<le> (h1 - 1) * (a_last - a_first + 1)"
    by simp
  moreover from `h1 \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "(h1 - 1) * (a_last - a_first + 1) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by simp
  with `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
    \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
  have "aux4_first + (h1 - 1) * (a_last - a_first + 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>"
    by simp
  ultimately show ?thesis using
    integer_to_int_upper [of aux4__last]
    `natural_in_range aux4_first`
    by (simp add: integer_in_range_def natural_in_range_def)
qed

why3_end

end
