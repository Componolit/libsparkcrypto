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
  from `m mod _ = _` word32_to_int_lower [of m]
  have "0 < \<lfloor>m\<rfloor>\<^sub>s"
    by (auto simp add: word32_to_int_def word_mod_def le_less)
  have "(- \<lfloor>m\<rfloor>\<^sub>s) mod Base = (Base - \<lfloor>m\<rfloor>\<^sub>s) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  with `0 < \<lfloor>m\<rfloor>\<^sub>s` word32_to_int_upper [of m]
  have minus_m: "(- \<lfloor>m\<rfloor>\<^sub>s) mod Base = Base - \<lfloor>m\<rfloor>\<^sub>s"
    by (simp only: mod_pos_pos_trivial)
  then have minus_m': "- \<lfloor>m\<rfloor>\<^sub>s mod Base mod \<lfloor>m\<rfloor>\<^sub>s = Base mod \<lfloor>m\<rfloor>\<^sub>s"
    by simp
  also from `0 < \<lfloor>m\<rfloor>\<^sub>s` have "Base mod \<lfloor>m\<rfloor>\<^sub>s < \<lfloor>m\<rfloor>\<^sub>s" by simp
  with word32_to_int_upper [of m] have "Base mod \<lfloor>m\<rfloor>\<^sub>s < Base" by simp
  with `0 < \<lfloor>m\<rfloor>\<^sub>s` have "Base mod \<lfloor>m\<rfloor>\<^sub>s = (Base - Base div \<lfloor>m\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s) mod Base"
    by (simp add: zmod_zdiv_equality' [symmetric]
      mod_pos_pos_trivial)
  also have "\<dots> = - (Base div \<lfloor>m\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  finally show ?thesis using
    `0 < \<lfloor>m\<rfloor>\<^sub>s` word32_to_int_upper [of m] minus_m
    by (simp only: word_uint_eq_iff uint_word_ariths uint_div uint_mod word32_to_int_def)
      (simp add: div_minus_self)
qed

why3_end

end
