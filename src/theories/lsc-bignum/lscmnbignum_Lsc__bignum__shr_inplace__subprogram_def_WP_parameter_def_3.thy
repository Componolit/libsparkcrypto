theory lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `i1 = result - 1` `\<not> a_first \<le> i1` `a_first \<le> result`
  have "result = a_first" by simp
  with
    `(num_of_big_int' (Array a2 _) _ _ = num_of_big_int' (Array a1 _) _ _ * _ + _) = _`
    `mk_map__ref a = mk_map__ref a1`
  show ?thesis
    by (simp add: diff_diff_eq2 diff_add_eq zdiv_zadd1_eq)
qed

why3_end

end
