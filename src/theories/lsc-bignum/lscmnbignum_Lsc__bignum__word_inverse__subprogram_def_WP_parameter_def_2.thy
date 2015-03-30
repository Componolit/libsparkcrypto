theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `WP_parameter_def.mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> 2 = 1` word32_to_int_lower [of m]
  have "0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>"
    by (auto simp add: mod_def emod_def le_less)
  have "(- \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) mod Base = (Base - \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  with `0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>` word32_to_int_upper [of m]
  have minus_m: "(- \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) mod Base = Base - \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>"
    by (simp only: mod_pos_pos_trivial)
  then have minus_m': "- \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> mod Base mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> = Base mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>"
    by simp

  from odd_coprime [OF `WP_parameter_def.mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> 2 = 1`
    [unfolded mod_def emod_def, simplified], of 32]
  have "coprime Base \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>" by (simp add: gcd_commute_int)
  also note gcd_red_int
  finally show ?thesis using
    minus_m' `0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = WP_parameter_def.mod ((0 - \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) emod Base) \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>`
    by (simp add: mod_def emod_def word32_coerce)
qed

why3_end

end
