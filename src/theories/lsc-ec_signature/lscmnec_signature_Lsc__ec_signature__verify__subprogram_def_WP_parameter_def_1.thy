theory lscmnec_signature_Lsc__ec_signature__verify__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__verify__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array lsc__ec__invert__b _) _ _ < _) = _`
  by (simp add: mk_bounds_eqs integer_in_range_def slide_eq)

why3_end

end
