theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_6
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array lsc__ec__point_add__z3 _) _ _ < num_of_big_int' m _ _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq)

why3_end

end
