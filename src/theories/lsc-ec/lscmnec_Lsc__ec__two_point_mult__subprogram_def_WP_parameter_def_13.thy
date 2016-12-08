theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_13
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_13.xml"

why3_vc WP_parameter_def
proof -
  have e: "e1_last - (i1 - 1) = 1 + (e1_last - i1)"
    by simp
  from
    `two_point_mult_spec _ _ _ _ _ _ _ _ _ _
       (num_of_big_int' (Array x32 _) _ _)
       (num_of_big_int' (Array y32 _) _ _)
       (num_of_big_int' (Array z32 _) _ _) = _`
    `i1 \<le> e1_last`
  show ?thesis
    by (simp add: e add_ac mult_ac word32_to_int_def two_point_mult_spec_def)
qed

why3_end

end
