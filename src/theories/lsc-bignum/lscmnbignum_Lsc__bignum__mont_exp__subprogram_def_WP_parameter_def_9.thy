theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_9.xml"

why3_vc WP_parameter_def
proof -
  have e: "e_last - (i1 - 1) = 1 + (e_last - i1)"
    by simp
  from `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `i1 \<le> e_last`
  show ?thesis
    by (simp add: e add_ac mult_ac word32_to_int_def)
qed

why3_end

end
