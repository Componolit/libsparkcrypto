theory lscmnec_Lsc__ec__on_curve__subprogram_def_WP_parameter_def_8
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__on_curve__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' b _ _ < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
