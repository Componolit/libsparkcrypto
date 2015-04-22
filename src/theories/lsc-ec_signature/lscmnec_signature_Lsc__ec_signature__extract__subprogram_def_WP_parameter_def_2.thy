theory lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__extract__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>x_last\<rfloor>\<^sub>\<nat> - \<lfloor>x_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' rn _ _ = _) = _`
    `(1 < num_of_big_int' n _ _) = _`
  by simp

why3_end

end
