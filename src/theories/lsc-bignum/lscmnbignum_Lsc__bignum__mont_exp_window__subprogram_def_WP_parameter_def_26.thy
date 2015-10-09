theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_26
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_26.xml"

why3_vc WP_parameter_def
proof -
  from `0 \<le> n` `a_first < a_last`
  have "0 \<le> n * (a_last - a_first + 1)"
    by simp
  moreover from `h1 \<le> 2 ^ nat k - 1` `n \<le> h1` `a_first < a_last`
  have "n * (a_last - a_first + 1) \<le>
    (2 ^ nat k - 1) * (a_last - a_first + 1)"
    by simp
  with `a_first < a_last`
  have "n * (a_last - a_first + 1) + (a_last - a_first) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by (simp add: sign_simps)
  ultimately show ?thesis using
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
    `a_first < a_last`
    `natural_in_range aux4_first`
    integer_to_int_upper [of aux4__last]
    by (simp add: natural_in_range_def)
qed

why3_end

end
