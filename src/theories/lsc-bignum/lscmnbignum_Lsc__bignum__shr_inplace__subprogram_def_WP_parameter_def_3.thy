theory lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `i1 = i2 - 1` `\<not> \<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i1` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i2`
  have "i2 = \<lfloor>a_first1\<rfloor>\<^sub>\<nat>" by simp
  with
    `(num_of_big_int' (Array a2 _) _ _ = num_of_big_int' (Array a1 _) _ _ * _ + _) = _`
    `mk_ref a = mk_ref a1`
  show ?thesis
    by (simp add: diff_diff_eq2 diff_add_eq zdiv_zadd1_eq)
qed

why3_end

end
