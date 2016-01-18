theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_21
imports "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_21.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array y3 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a2 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a3 _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq sub_less_mod)

why3_end

end
