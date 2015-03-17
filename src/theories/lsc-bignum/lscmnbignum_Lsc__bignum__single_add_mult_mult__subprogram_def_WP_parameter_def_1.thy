theory lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  have "(\<lfloor>o11\<rfloor>\<^bsub>w64\<^esub> + \<lfloor>shr \<lfloor>o3\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> + \<lfloor>shr \<lfloor>o6\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> + \<lfloor>shr \<lfloor>o9\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub>) mod
    18446744073709551616 \<le> 18446744073709551615"
    by simp
  from this [THEN zdiv_mono1, of Base, simplified]
    `\<lfloor>o12\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>shr \<lfloor>o12\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> = _`
  show ?thesis
    by (simp add: word32_in_range_def ediv_def emod_def)
qed

why3_end

end
