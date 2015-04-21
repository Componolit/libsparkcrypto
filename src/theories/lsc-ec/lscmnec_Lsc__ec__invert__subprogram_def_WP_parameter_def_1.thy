theory lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>o3\<rfloor>\<^sub>\<nat> = \<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' r _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by simp

why3_end

end
