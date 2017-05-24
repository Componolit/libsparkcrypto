theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_20
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_20.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array x2 _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by (simp add: map__content_def)

why3_end

end
