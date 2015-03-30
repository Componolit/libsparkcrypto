theory lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
  using `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = 0`
  by simp

why3_end

end
