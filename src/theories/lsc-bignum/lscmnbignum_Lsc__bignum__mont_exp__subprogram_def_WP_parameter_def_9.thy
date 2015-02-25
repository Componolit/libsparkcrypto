theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9.xml"

why3_vc WP_parameter_def
proof -
  have e: "\<lfloor>e_last\<rfloor>\<^sub>\<nat> - (i - 1) = 1 + (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - i)"
    by simp
  from `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `i \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>` `\<not> 0 \<le> j` `j = j1 - 1` `0 \<le> j1`
  show ?thesis
    by (simp add: e add_ac mult_ac)
qed

why3_end

end
