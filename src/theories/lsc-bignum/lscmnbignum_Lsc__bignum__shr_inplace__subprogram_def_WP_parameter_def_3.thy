theory lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    `mk_int__ref i = mk_int__ref a_first`
    `(num_of_big_int' (Array a2 _) _ _ = num_of_big_int' (Array a1 _) _ _ * _ + _) = _`
    `mk_map__ref a = mk_map__ref a1`
  by (simp add: diff_diff_eq2 diff_add_eq zdiv_zadd1_eq)

why3_end

end
