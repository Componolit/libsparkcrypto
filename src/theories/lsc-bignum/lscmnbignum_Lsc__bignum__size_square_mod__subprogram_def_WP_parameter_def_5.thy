theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat> + 1"
  let ?r = "num_of_big_int (word32_to_int o r2) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?l"

  from `carry \<noteq> True`
    `(num_of_big_int' (Array r2 _) _ _ * 2 = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>r_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat>)`
    `(if WP_parameter_def.less _ _ _ _ _ \<noteq> _ then _ else _) \<noteq> _`
    `(WP_parameter_def.less _ _ _ _ _ = _) = _`
  have "num_of_big_int (word32_to_int o r3) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l = (?r * 2) mod ?m"
    by (simp add: num_of_lint_lower word32_to_int_lower mod_pos_pos_trivial)
  then show ?thesis using `(num_of_big_int' (Array r2 _) _ _ = _) = _` `0 \<le> j`
    by (simp add: nat_add_distrib mult_ac)
qed

why3_end

end
