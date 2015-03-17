theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_54
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_54.xml"

why3_vc WP_parameter_def
  using `\<lfloor>shr32 \<lfloor>w1\<rfloor>\<^bsub>w32\<^esub> 1\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>w1\<rfloor>\<^bsub>w32\<^esub> ediv 2 ^ nat 1`
    zdiv_mono1 [OF word32_to_int_upper, of 2, simplified]
  by (simp add: natural_in_range_def ediv_def
    word32_to_int_lower pos_imp_zdiv_nonneg_iff)

why3_end

end
