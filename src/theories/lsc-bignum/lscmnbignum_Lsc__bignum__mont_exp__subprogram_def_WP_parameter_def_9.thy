theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9.xml"

why3_vc WP_parameter_def
proof -
  have e: "e_last - (result2 - 1) = 1 + (e_last - result2)"
    by simp
  from `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `result2 \<le> e_last` `\<not> 0 \<le> j` `j = result3 - 1` `0 \<le> result3`
  show ?thesis
    by (simp add: e add_ac mult_ac word32_to_int_def)
qed

why3_end

end
