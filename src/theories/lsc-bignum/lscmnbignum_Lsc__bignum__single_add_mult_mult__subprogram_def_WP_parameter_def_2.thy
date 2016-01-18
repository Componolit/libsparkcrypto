theory lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

lemma uint_down_ucast:
  "len_of TYPE('b) < len_of TYPE('a) \<Longrightarrow>
   uint ((ucast :: 'a::len0 word \<Rightarrow> 'b::len0 word) x) = uint x mod 2 ^ len_of TYPE('b)"
  by (simp add: ucast_def uint_word_of_int)

lemma mod_div_mod: "(x::int) mod 2 ^ (m + n) div 2 ^ m mod 2 ^ n = x mod 2 ^ (m + n) div 2 ^ m"
proof -
  have "x mod 2 ^ (m + n) \<le> 2 ^ (m + n) + (- 1)" by simp
  then have "x mod 2 ^ (m + n) div 2 ^ m \<le> (2 ^ (m + n) + (- 1)) div 2 ^ m"
    by (rule zdiv_mono1) simp
  then have "x mod 2 ^ (m + n) div 2 ^ m < 2 ^ n"
    by (simp add: power_add div_eq_minus1 del: add_uminus_conv_diff)
  then show ?thesis
    by (simp add: pos_imp_zdiv_nonneg_iff mod_pos_pos_trivial)
qed

lemma mult64_mod_eq:
  "\<lfloor>x\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s mod 18446744073709551616 = \<lfloor>x\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s"
  using mult_strict_mono [OF word32_to_int_upper' [of x] word32_to_int_upper' [of y]]
  by (simp add: mod_pos_pos_trivial word32_to_int_lower)

why3_open "lscmnbignum_Lsc__bignum__single_add_mult_mult__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  let ?x = "\<lfloor>a\<rfloor>\<^sub>s + \<lfloor>carry1\<rfloor>\<^sub>s + \<lfloor>v\<rfloor>\<^sub>s * \<lfloor>w\<rfloor>\<^sub>s mod Base + \<lfloor>x\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s mod Base"
  let ?y = "\<lfloor>carry2\<rfloor>\<^sub>s + \<lfloor>v\<rfloor>\<^sub>s * \<lfloor>w\<rfloor>\<^sub>s div Base + \<lfloor>x\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s div Base"
  let ?k = "18446744073709551616"

  have "\<lfloor>a\<rfloor>\<^sub>s + \<lfloor>v\<rfloor>\<^sub>s * \<lfloor>w\<rfloor>\<^sub>s + \<lfloor>x\<rfloor>\<^sub>s * \<lfloor>y\<rfloor>\<^sub>s + \<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s =
    ?x mod Base + (?x div Base) * Base + Base * ?y"
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
  finally show ?thesis
    by (simp add:
      base_eq uint_word_ariths
      uint_up_ucast is_up uint_down_ucast
      shiftr_div_2n uint_and AND_mod [where n=32, simplified]
      mult64_mod_eq [unfolded word32_to_int_def])
      (simp add: word32_to_int_def [symmetric]
        mod_div_mod [of _ 32 32, simplified]
        arg_cong [OF mod_div_equality2 [simplified add.commute, of _ Base],
          of "op * Base", simplified])
qed

why3_end

end
