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
  have eq: "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - (i - 1) = 1 + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - i)"
    by simp
  have
    "(\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> + \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>)) mod Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> +
     \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> =
     (\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> +
      \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>) * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> mod (Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)) mod
       (Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>) +
     \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>"
    by (simp add: mod_mult_mult2 ring_distribs [symmetric])
  also from `\<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 32`
  have "\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>) * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> = Base * \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub>"
    by (simp add: nat_diff_distrib power_add [symmetric] natural_to_int_lower)
  also have "Base * \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod (Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>) = Base * (\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)"
    by simp
  also have "\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> < Base"
    by (auto simp add: zdiv_zmod_equality' word32_to_int_lower word32_to_int_upper'
      intro: add_less_le_mono [of _ _ "- (\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)" 0,
      simplified])
  then have "\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> +
      Base * (\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>) < Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>"
    by (rule two_words_upper) simp_all
  then have "(\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> +
      Base * (\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)) mod (Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>) =
    \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> + Base * (\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)"
    by (simp add: mod_pos_pos_trivial
      mult_nonneg_nonneg pos_imp_zdiv_nonneg_iff word32_to_int_lower)
  finally
  have "(\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> + \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>)) mod Base * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> +
    \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> =
    \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> + Base * (\<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> mod 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>)"
    by (simp add: mod_div_equality)
  moreover from
    `\<forall>j. \<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> j \<and> j \<le> i \<longrightarrow> \<lfloor>a1 j\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a j\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
  have "\<lfloor>a i\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub>" by simp
  ultimately show ?thesis
  using
    `i \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `\<lfloor>shr32 \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> \<lfloor>k\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> ediv 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>`
    `\<lfloor>shl32 \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>) emod Base`
    `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = (\<lfloor>shr32 \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> \<lfloor>k\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>shl32 \<lfloor>h1\<rfloor>\<^bsub>w32\<^esub> (32 - \<lfloor>k\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub>) emod Base`
    by (simp add: eq ring_distribs ediv_def emod_def fun_upd_comp)
qed

why3_end

end
