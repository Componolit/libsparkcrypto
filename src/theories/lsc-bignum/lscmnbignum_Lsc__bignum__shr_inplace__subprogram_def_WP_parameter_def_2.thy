theory lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

lemma zdiv_zmod_equality': "(m::int) div n * n = m - m mod n"
  by (simp add: zmod_zdiv_equality')

lemma two_words_upper:
  assumes "(x::int) < a" "y < b" "0 \<le> a"
  shows "x + a * y < a * b"
proof -
  from `y < b` have "y \<le> b - 1" by simp
  then have "a * y \<le> a * (b - 1)" using `0 \<le> a`
    by (rule mult_left_mono)
  with `x < a` show ?thesis by (simp add: ring_distribs)
qed

why3_open "lscmnbignum_Lsc__bignum__shr_inplace__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  have eq: "a_last - (o1 - 1) = 1 + (a_last - o1)"
    by simp
  have
    "(\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k + \<lfloor>h11\<rfloor>\<^sub>s * 2 ^ nat (32 - k)) mod Base * 2 ^ nat k +
     \<lfloor>a o1\<rfloor>\<^sub>s mod 2 ^ nat k =
     (\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k * 2 ^ nat k +
      \<lfloor>h11\<rfloor>\<^sub>s * 2 ^ nat (32 - k) * 2 ^ nat k mod (Base * 2 ^ nat k)) mod
       (Base * 2 ^ nat k) +
     \<lfloor>a o1\<rfloor>\<^sub>s mod 2 ^ nat k"
    by (simp add: mod_mult_mult2 ring_distribs [symmetric])
  also from `k \<le> 32` `natural_in_range k`
  have "\<lfloor>h11\<rfloor>\<^sub>s * 2 ^ nat (32 - k) * 2 ^ nat k = Base * \<lfloor>h11\<rfloor>\<^sub>s"
    by (simp add: nat_diff_distrib power_add [symmetric] natural_in_range_def)
  also have "Base * \<lfloor>h11\<rfloor>\<^sub>s mod (Base * 2 ^ nat k) = Base * (\<lfloor>h11\<rfloor>\<^sub>s mod 2 ^ nat k)"
    by simp
  also have "\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k * 2 ^ nat k < Base"
    by (auto simp add: zdiv_zmod_equality' word32_to_int_lower word32_to_int_upper'
      intro: add_less_le_mono [of _ _ "- (\<lfloor>a o1\<rfloor>\<^sub>s mod 2 ^ nat k)" 0,
      simplified])
  then have "\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k * 2 ^ nat k +
      Base * (\<lfloor>h11\<rfloor>\<^sub>s mod 2 ^ nat k) < Base * 2 ^ nat k"
    by (rule two_words_upper) simp_all
  then have "(\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k * 2 ^ nat k +
      Base * (\<lfloor>h11\<rfloor>\<^sub>s mod 2 ^ nat k)) mod (Base * 2 ^ nat k) =
    \<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k * 2 ^ nat k + Base * (\<lfloor>h11\<rfloor>\<^sub>s mod 2 ^ nat k)"
    by (simp add: mod_pos_pos_trivial
      pos_imp_zdiv_nonneg_iff word32_to_int_lower)
  finally
  have "(\<lfloor>a o1\<rfloor>\<^sub>s div 2 ^ nat k + \<lfloor>h11\<rfloor>\<^sub>s * 2 ^ nat (32 - k)) mod Base * 2 ^ nat k +
    \<lfloor>a o1\<rfloor>\<^sub>s mod 2 ^ nat k =
    \<lfloor>a o1\<rfloor>\<^sub>s + Base * (\<lfloor>h11\<rfloor>\<^sub>s mod 2 ^ nat k)"
    by (simp add: mod_div_equality)
  moreover from
    `\<forall>j. a_first \<le> j \<and> j \<le> o1 \<longrightarrow> a1 j = a j`
    `a_first \<le> o1`
  have "\<lfloor>a o1\<rfloor>\<^sub>s = \<lfloor>a1 o1\<rfloor>\<^sub>s" by simp
  ultimately show ?thesis
  using
    `o1 \<le> a_last`
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    BV32.facts.to_uint_lsr [of "a1 o1" "of_int k"]
    BV32.facts.to_uint_lsl [of h11 "of_int (32 - k)"]
    `o2 = _` `natural_in_range k` `natural_in_range (32 - k)`
    by (simp add: eq ring_distribs ediv_def emod_def fun_upd_comp
      word32_to_int_def uint_word_ariths uint_div uint_pow
      BV32.facts.to_uint_of_int BV32.uint_in_range_def natural_in_range_def
      mod_pos_pos_trivial)
qed

why3_end

end
