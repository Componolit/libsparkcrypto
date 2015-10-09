theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_18
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_18.xml"

why3_vc WP_parameter_def
proof -
  from `h1 \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "(h1 - 1) * (a_last - a_first + 1) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by simp

  with
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le> \<lfloor>aux4__last\<rfloor>\<^sub>\<int>`
  show ?thesis by (simp add: mk_bounds_snd)
qed

why3_end

end
