theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_5
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using `two_point_mult_spec (num_of_big_int' m _ _) _ _ _ _ _ _ _ _ _ _ _ _= _`
  by (simp add: two_point_mult_spec_def div_pos_pos_trivial uint_lt [where 'a=32, simplified])

why3_end

end
