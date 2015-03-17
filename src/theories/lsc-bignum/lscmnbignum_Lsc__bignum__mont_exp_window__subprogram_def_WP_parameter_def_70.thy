theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_70.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 30`
  have "(2::int) ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 2 ^ nat 30"
    by (simp only: power_increasing_iff)
  then show ?thesis by simp
qed

why3_end

end
