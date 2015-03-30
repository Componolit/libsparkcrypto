theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_1
imports "../LibSPARKcrypto"
begin

lemma div_minus_self:
  assumes "(b::int) \<noteq> 0"
  shows "(a - b) div b = a div b - 1"
proof -
  from assms have "a div b = (a - b) div b + 1"
    by (simp add: div_add_self2 [symmetric])
  then show ?thesis by simp
qed

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_1.xml"

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
  also from `0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>` have "Base mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>" by simp
  with word32_to_int_upper [of m] have "Base mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> < Base" by simp
  with `0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>` have "Base mod \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> = (Base - Base div \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) mod Base"
    by (simp add: zmod_zdiv_equality' [symmetric]
      mod_pos_pos_trivial)
  also have "\<dots> = - (Base div \<lfloor>m\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  finally show ?thesis using
    `0 < \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>` word32_to_int_upper [of m]
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = WP_parameter_def.mod ((0 - \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) emod Base) \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>o3\<rfloor>\<^bsub>w32\<^esub> = ((0 - (0 - \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) emod Base ediv \<lfloor>m\<rfloor>\<^bsub>w32\<^esub>) emod Base - 1) emod Base`
    by (simp add: minus_m div_minus_self emod_def ediv_def mod_def)
qed

why3_end

end
