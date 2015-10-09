theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_13
imports "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_13.xml"

why3_vc WP_parameter_def
proof -
  note [simp] = mk_bounds_eqs integer_in_range_def slide_eq
  from `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  show ?thesis
    apply simp
    apply (simp only:
      `(num_of_big_int' (Array lsc__bignum__mod_sub_inplace__a2 _) _ _ = _) = _`
      [simplified])
    apply (rule sub_less_mod [THEN less_imp_le])
    apply (simp only:
      `(num_of_big_int' (Array lsc__bignum__mod_sub_inplace__a1 _) _ _ = _) = _`
      [simplified])
    apply (rule sub_less_mod)
    apply (simp add:
      `(num_of_big_int' (Array lsc__bignum__mont_mult__a6 _) _ _ = _) = _`
      [simplified])
    apply (simp_all add:
      `(num_of_big_int' (Array lsc__bignum__mont_mult__a5 _) _ _ = _) = _`
      [simplified])
    done
qed

why3_end

end
