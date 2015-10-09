theory lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' (Array v1 _) _ _ = _) = _`
    `(math_int_from_word (of_int 1) < num_of_big_int' n _ _) = _`
  by simp

why3_end

end
