theory lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array b _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
