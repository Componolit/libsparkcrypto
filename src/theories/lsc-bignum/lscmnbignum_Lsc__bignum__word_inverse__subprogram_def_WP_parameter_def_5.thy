theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
  using
    `lsc__bignum__word_inverse__result = o1`
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = (0 - \<lfloor>p\<rfloor>\<^bsub>w32\<^esub>) emod Base`
    `\<lfloor>\<lceil>gcd \<lfloor>a2\<rfloor>\<^bsub>w32\<^esub> \<lfloor>b2\<rfloor>\<^bsub>w32\<^esub>\<rceil>\<^bsub>w32\<^esub>\<rfloor>\<^bsub>w32\<^esub> = 1`
    `\<lfloor>a2\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>p2\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
    `\<lfloor>b2\<rfloor>\<^bsub>w32\<^esub> = 0`
    `mk_ref p = mk_ref p2`
  by (simp add: emod_def word32_coerce zdiff_zmod_right [of _ "\<lfloor>p2\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>", symmetric])

why3_end

end
