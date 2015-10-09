theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

lemma zdiv_zmod_equality': "(m::int) div n * n = m - m mod n"
  by (simp add: zmod_zdiv_equality')

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `result5 * m \<noteq> of_int 0`
    have "0 < \<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base"
      by (simp add: word_uint_eq_iff uint_word_ariths word32_to_int_def)
  then have "\<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base mod (\<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base) < \<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base"
    by simp
  then have "\<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base mod (\<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base) < Base" by simp
  with `0 < \<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base`
  have "\<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base mod (\<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base) =
    (\<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s - \<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base div (\<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base) *
     (\<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base)) mod Base"
    by (simp add: zdiv_zmod_equality'
      zdiff_zmod_left [of "\<lfloor>result4\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s", symmetric] mod_pos_pos_trivial)
  also note zdiff_zmod_right
  also note mod_mult_right_eq
  finally show ?thesis using
    `0 < \<lfloor>result5\<rfloor>\<^sub>s * \<lfloor>m\<rfloor>\<^sub>s mod Base`
    by (simp add: ring_distribs mult.assoc word32_to_int_def
      word_uint_eq_iff uint_word_ariths uint_div uint_mod del: uint_inject)
qed

why3_end

end
