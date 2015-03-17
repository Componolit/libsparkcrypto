theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_38
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_38.xml"

why3_vc WP_parameter_def
  using `\<lfloor>o5\<rfloor>\<^sub>\<nat> = 1`
  by (simp add: word64_to_int_lower)

why3_end

end
