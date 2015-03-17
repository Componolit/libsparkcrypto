theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_34
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_34.xml"

why3_vc WP_parameter_def
proof -
  have "0 < (2::int) ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>" by simp
  with `\<not> (1 \<le> h \<and> h \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1)` `h = 1`
  have "(2::int) ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> = 1" by (simp del: zero_less_power)
  with
    `(num_of_big_int' (Array aux4 _) _ _ = _) = _`
    `0 \<le> n` `n \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1`
  show ?thesis by simp
qed

why3_end

end
