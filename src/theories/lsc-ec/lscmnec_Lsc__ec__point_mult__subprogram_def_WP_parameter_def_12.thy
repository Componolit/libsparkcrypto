theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_12
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_12.xml"

why3_vc WP_parameter_def
  using
    `point_mult_spec _ _ _ _ _ _
       (num_of_big_int' (Array x21 _) _ _)
       (num_of_big_int' (Array y21 _) _ _)
       (num_of_big_int' (Array z21 _) _ _) = _`
    `e_first \<le> e_last`
  by (simp add: point_mult_spec_def word32_to_int_def base_eq add.commute mult.commute map__content_def)

why3_end

end
