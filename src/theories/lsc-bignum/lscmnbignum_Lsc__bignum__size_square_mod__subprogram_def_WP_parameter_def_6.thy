theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
proof -
  from `j = result4 + 1` `\<not> j \<le> 63` `result4 \<le> 63`
  have "result4 = 63" by simp
  with
    `(num_of_big_int' (Array r1 _) _ _ = _) = _`
    `m_first \<le> result3`
  show ?thesis
    by (simp add: diff_add_eq [symmetric] nat_add_distrib mult_ac base_eq)
qed

why3_end

end
