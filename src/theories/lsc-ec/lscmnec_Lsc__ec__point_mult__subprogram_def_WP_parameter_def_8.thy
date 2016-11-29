theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_8
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
  using `point_mult_spec (num_of_big_int' m _ _) _ _ _ _ _ _ _ _ = _`
  by (simp add: point_mult_spec_def div_pos_pos_trivial uint_lt [where 'a=32, simplified])

why3_end

end
