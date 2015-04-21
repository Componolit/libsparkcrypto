theory lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_11
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__uncompress_point__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a4 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq)

why3_end

end