theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

lemma zdiv_zmod_equality': "(m::int) div n * n = m - m mod n"
  by (simp add: zmod_zdiv_equality')

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> \<noteq> 0` word32_to_int_lower [of b]
    `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
  have "0 < \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base"
    by (simp add: emod_def)
  then have "\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base mod (\<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base) < \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base"
    by simp
  then have "\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base mod (\<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base) < Base" by simp
  with `0 < \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base`
  have "\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base mod (\<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base) =
    (\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> - \<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base div (\<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base) *
     (\<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base)) mod Base"
    by (simp add: zdiv_zmod_equality'
      zdiff_zmod_left [of "\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>", symmetric] mod_pos_pos_trivial)
  also note zdiff_zmod_right
  also note mod_mult_right_eq
  finally show ?thesis using
    `0 < \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base`
    `\<lfloor>o4\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a\<rfloor>\<^bsub>w32\<^esub> ediv \<lfloor>b\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>o5\<rfloor>\<^bsub>w32\<^esub> = WP_parameter_def.mod \<lfloor>a\<rfloor>\<^bsub>w32\<^esub> \<lfloor>b\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>o6\<rfloor>\<^bsub>w32\<^esub> = (\<lfloor>p\<rfloor>\<^bsub>w32\<^esub> - \<lfloor>o4\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base`
    `\<lfloor>a\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>p\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
    `\<lfloor>b\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>q\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> emod Base`
    by (simp add: ediv_def emod_def mod_def ring_distribs mult.assoc)
qed

why3_end

end
