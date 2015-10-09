theory lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__word_inverse__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `m mod _ = _` word32_to_int_lower [of m]
  have "0 < \<lfloor>m\<rfloor>\<^sub>s"
    by (auto simp add: word_mod_def word32_to_int_def le_less)
  have "(- \<lfloor>m\<rfloor>\<^sub>s) mod Base = (Base - \<lfloor>m\<rfloor>\<^sub>s) mod Base"
    by (simp add: zdiff_zmod_left [of Base, symmetric])
  with `0 < \<lfloor>m\<rfloor>\<^sub>s` word32_to_int_upper [of m]
  have minus_m: "(- \<lfloor>m\<rfloor>\<^sub>s) mod Base = Base - \<lfloor>m\<rfloor>\<^sub>s"
    by (simp only: mod_pos_pos_trivial)
  then have minus_m': "- \<lfloor>m\<rfloor>\<^sub>s mod Base mod \<lfloor>m\<rfloor>\<^sub>s = Base mod \<lfloor>m\<rfloor>\<^sub>s"
    by simp

  from odd_coprime [OF `m mod _ = _`
    [simplified word_uint_eq_iff uint_mod, simplified], of 32]
  have "coprime Base \<lfloor>m\<rfloor>\<^sub>s" by (simp add: gcd_commute_int word32_to_int_def)
  also note gcd_red_int
  finally show ?thesis using
    minus_m' `0 < \<lfloor>m\<rfloor>\<^sub>s`
    by (simp add: word32_to_int_def word_of_int uint_mod uint_word_ariths)
qed

why3_end

end
