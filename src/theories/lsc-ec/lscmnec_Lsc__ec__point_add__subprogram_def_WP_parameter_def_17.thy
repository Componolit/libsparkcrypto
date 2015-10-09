theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_17
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_17.xml"

why3_vc WP_parameter_def
  using
    `x3 = x31` `l = x1_last - x1_first`
    `(num_of_big_int' (Array x31 _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
