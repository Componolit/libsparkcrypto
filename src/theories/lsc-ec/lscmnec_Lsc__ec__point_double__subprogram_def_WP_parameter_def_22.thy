theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_22
imports "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_22.xml"

why3_vc WP_parameter_def
  using
    `y2 = y21` `l = o1`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array y21 _) _ _ = _) = _`
    `(num_of_big_int' (Array y22 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
    `h1 = slide lsc__bignum__mont_mult__a1 _ _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a1 _) _ _ = _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq sub_less_mod)

why3_end

end