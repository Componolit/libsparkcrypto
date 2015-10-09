theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' y1 _ _ < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
