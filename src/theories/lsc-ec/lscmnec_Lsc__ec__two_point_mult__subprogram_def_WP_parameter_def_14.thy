theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_14
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_14.xml"

why3_vc WP_parameter_def
  using
    `two_point_mult_spec _ _ _ _ _ _ _ _ _ _
       (num_of_big_int' (Array x31 _) _ _)
       (num_of_big_int' (Array y31 _) _ _)
       (num_of_big_int' (Array z31 _) _ _) = _`
    `mk_map__ref x32 = mk_map__ref x31`
    `mk_map__ref x33 = mk_map__ref x32`
    `mk_map__ref y32 = mk_map__ref y31`
    `mk_map__ref y33 = mk_map__ref y32`
    `mk_map__ref z32 = mk_map__ref z31`
    `mk_map__ref z33 = mk_map__ref z32`
    `e1_first \<le> e1_last`
  by (simp add: two_point_mult_spec_def word32_to_int_def base_eq add.commute mult.commute)

why3_end

end
