theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_12
imports "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_12.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x1_last\<rfloor>\<^sub>\<nat> - \<lfloor>x1_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__bignum__mod_sub_inplace__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a7 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a10 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq less_imp_le [OF sub_less_mod])

why3_end

end
