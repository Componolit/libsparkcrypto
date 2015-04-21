theory lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_Lsc__ec__invert__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array b _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  by simp

why3_end

end