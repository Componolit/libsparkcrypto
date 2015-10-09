theory lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  show ?C1
    by (simp_all add: BV64.ule_def)
  from zdiv_mono1
    [OF uint_lt [where 'a=64, simplified zle_diff1_eq [symmetric]], of Base]
  show ?C2
    by (simp add: BV64.ule_def shiftr_div_2n)
qed

why3_end

end
