theory lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

lemma mult64_mod_eq:
  "\<lfloor>x\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> mod 18446744073709551616 = \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub>"
  using mult_strict_mono [OF word32_to_int_upper' [of x] word32_to_int_upper' [of y]]
  by (simp add: mod_pos_pos_trivial word32_to_int_lower)

why3_open "lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  let ?x = "\<lfloor>a\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>v\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> mod Base + \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> mod Base"
  let ?y = "\<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>v\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> div Base + \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> div Base"
  let ?k = "18446744073709551616"

  have "\<lfloor>a\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>v\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> =
    ?x mod Base + (?x div Base) * Base (*?x*) + Base * ?y"
    by (simp only: semiring_div_class.mod_div_equality') simp
  also have "\<dots> = ?x mod Base + Base * (?y + ?x div Base)"
    by simp
  also from word32_to_int_upper [of a] word32_to_int_upper [of carry1]
  have "?x div Base < 4"
    by simp
  then have "?y + ?x div Base < 3 * Base"
  using
    zdiv_mono1
      [OF mult_mono [OF word32_to_int_upper [of v] word32_to_int_upper [of w] _
         word32_to_int_lower [of w]], of Base]
    zdiv_mono1
      [OF mult_mono [OF word32_to_int_upper [of x] word32_to_int_upper [of y] _
         word32_to_int_lower [of y]], of Base]
    word32_to_int_upper [of carry2]
    by simp
  then have "?y + ?x div Base = (?y + ?x div Base) mod ?k"
    by (simp add: mod_pos_pos_trivial word32_to_int_lower pos_imp_zdiv_nonneg_iff)
  also from word32_to_int_upper [of a] word32_to_int_upper [of carry1]
  have "?x < 4 * Base"
    by simp
  then have "?x = ?x mod ?k"
    by (simp add: mod_pos_pos_trivial word32_to_int_lower)
  finally show ?thesis using
    `\<lfloor>a1\<rfloor>\<^bsub>w32\<^esub> = _` `\<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub> = _` `\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> = _`
    `\<lfloor>o11\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o10\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o9\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o8\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o7\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>o6\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o5\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o4\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o3\<rfloor>\<^bsub>w64\<^esub> = _` `\<lfloor>o2\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>o1\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>shr \<lfloor>o11\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>shr \<lfloor>o3\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>shr \<lfloor>o6\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> = _`
    `\<lfloor>shr \<lfloor>o9\<rfloor>\<^bsub>w64\<^esub> 32\<rfloor>\<^bsub>w64\<^esub> = _`
    by (simp add: emod_def ediv_def mult64_mod_eq base_eq)
qed

why3_end

end
