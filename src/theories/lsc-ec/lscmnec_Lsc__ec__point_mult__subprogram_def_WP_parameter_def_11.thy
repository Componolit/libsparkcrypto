theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_11
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
proof -
  have e: "e_last - (i1 - 1) = 1 + (e_last - i1)"
    by simp
  from
    `point_mult_spec _ _ _ _ _ _
       (num_of_big_int' (Array x22 _) _ _)
       (num_of_big_int' (Array y22 _) _ _)
       (num_of_big_int' (Array z22 _) _ _) = _`
    `i1 \<le> e_last`
  show ?thesis
    by (simp add: e add_ac mult_ac word32_to_int_def point_mult_spec_def)
qed

why3_end

end
