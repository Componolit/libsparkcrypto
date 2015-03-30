theory lscmnbignum_Lsc__bignum__sub_inplace__subprogram_def_WP_parameter_def_4
imports "../Sub"
begin

why3_open "lscmnbignum_Lsc__bignum__sub_inplace__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
  have "num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (i + 1 - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) -
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (i + 1 - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) =
    num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) -
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    (Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>a i\<rfloor>\<^bsub>w32\<^esub> -
     Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub>)"
    by (simp add: diff_add_eq [symmetric])
  moreover from `\<forall>k. i \<le> k \<and> k \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>a1 k\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a k\<rfloor>\<^bsub>w32\<^esub>`
    `i \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "\<lfloor>a i\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub>" by simp
  moreover from
    `(if \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts b \<lfloor>o2\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> then _ else _) \<noteq> _`
    `(if \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>elts b \<lfloor>o2\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> then _ else _) \<noteq> _`
  have "num_of_bool False = num_of_bool
    (\<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts b \<lfloor>o2\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> \<or> \<lfloor>a1 i\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>elts b \<lfloor>o2\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> \<and> carry)"
    by simp
  ultimately show ?thesis using
    `(num_of_big_int' (Array a _) _ _ - num_of_big_int' b _ _ = _) = _`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = _`
    `\<lfloor>o2\<rfloor>\<^sub>\<nat> = \<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>)`
    `(\<lfloor>word_of_boolean carry\<rfloor>\<^bsub>w32\<^esub> = num_of_bool carry) = _`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib
      sub_carry [of _ Base] div_mod_eq ring_distribs base_eq
      word32_to_int_lower word32_to_int_upper' emod_def fun_upd_comp
      del: num_of_bool.simps)
qed

why3_end

end
