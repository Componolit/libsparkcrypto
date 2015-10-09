theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' x1 _ _ < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
