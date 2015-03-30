theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_7
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_7.xml"

why3_vc WP_parameter_def
proof -
  from `j2 = j3 + 1` `\<not> j2 \<le> 63` `j3 \<le> 63`
  have "j3 = 63" by simp
  moreover from `i1 = i2 + 1` `\<not> i1 \<le> \<lfloor>m_last\<rfloor>\<^sub>\<nat>` `i2 \<le> \<lfloor>m_last\<rfloor>\<^sub>\<nat>`
  have "i2 = \<lfloor>m_last\<rfloor>\<^sub>\<nat>" by simp
  ultimately show ?thesis using
    `mk_ref r = mk_ref r1`
    `mk_ref r1 = mk_ref r2`
    `(num_of_big_int' (Array r2 _) _ _ = _) = _`
    `\<lfloor>m_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>m_last\<rfloor>\<^sub>\<nat>`
    by (simp add: nat_add_distrib mult_ac base_eq)
qed

why3_end

end
