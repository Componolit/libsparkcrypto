theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> \<noteq> 0` word32_to_int_lower [of b]
    `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
  have "0 < \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base"
    by (simp add: emod_def)
  with
    `\<lfloor>o5\<rfloor>\<^bsub>w32\<^esub> = WP_parameter_def.mod \<lfloor>a\<rfloor>\<^bsub>w32\<^esub> \<lfloor>b\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>a\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
    `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
    `\<lfloor>\<lceil>gcd \<lfloor>a\<rfloor>\<^bsub>w32\<^esub> \<lfloor>b\<rfloor>\<^bsub>w32\<^esub>\<rceil>\<^bsub>w32\<^esub>\<rfloor>\<^bsub>w32\<^esub> = 1`
  show ?thesis
    by (simp add: emod_def mod_def word32_coerce gcd_red_int [symmetric])
qed

why3_end

end
