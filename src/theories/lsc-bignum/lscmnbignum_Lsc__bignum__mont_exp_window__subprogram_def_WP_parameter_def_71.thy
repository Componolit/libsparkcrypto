theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_71
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_71.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 30`
  have "(2::int) ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 2 ^ nat 30"
    by (simp only: power_increasing_iff)
  with `n \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1` `0 \<le> n`
  show ?thesis by (simp add: natural_in_range_def)
qed

why3_end

end
