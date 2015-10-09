theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_25
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_25.xml"

why3_vc WP_parameter_def
  using
    `z3 = z31` `l = x1_last - x1_first`
    `(num_of_big_int' (Array z31 _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
