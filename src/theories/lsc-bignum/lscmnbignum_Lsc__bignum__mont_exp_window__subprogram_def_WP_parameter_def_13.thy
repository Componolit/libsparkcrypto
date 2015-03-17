theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_13
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_13.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 30`
  have "nat \<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 30" by simp
  then have "(2::int) ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 2 ^ 30"
    by (rule power_increasing) simp
  with `0 \<le> n` `n \<le> h - 1` `h \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1`
  show ?thesis by (simp add: natural_in_range_def)
qed

why3_end

end
