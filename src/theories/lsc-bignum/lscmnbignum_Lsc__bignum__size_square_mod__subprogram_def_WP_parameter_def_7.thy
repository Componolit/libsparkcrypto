theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_7
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_7.xml"

why3_vc WP_parameter_def
proof -
  from `j2 = result1 + 1` `\<not> j2 \<le> 63` `result1 \<le> 63`
  have "result1 = 63" by simp
  moreover from `i1 = result + 1` `\<not> i1 \<le> m_last` `result \<le> m_last`
  have "result = m_last" by simp
  ultimately show ?thesis using
    `mk_map__ref r = mk_map__ref r1`
    `mk_map__ref r1 = mk_map__ref r2`
    `(num_of_big_int' (Array r2 _) _ _ = _) = _`
    `m_first \<le> m_last`
    by (simp add: nat_add_distrib mult_ac base_eq)
qed

why3_end

end
