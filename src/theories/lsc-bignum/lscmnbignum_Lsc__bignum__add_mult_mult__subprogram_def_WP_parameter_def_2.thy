theory lscmnbignum_Lsc__bignum__add_mult_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__add_mult_mult__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  note inv = `(num_of_big_int' (Array a _) _ _ + num_of_big_int' b _ _ * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
    num_of_big_int' c _ _ * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + _ * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> = _) = _`
    [simplified base_eq, simplified]
  note single =
    `(\<lfloor>a1 _\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>elts b _\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>elts c _\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> +
      \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub> + _ * \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> = _) = _`
    [simplified, simplified base_eq]
  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i` `i \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
    `\<forall>k. i \<le> k \<and> k \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat> + 1 \<longrightarrow> \<lfloor>a1 k\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>a k\<rfloor>\<^bsub>w32\<^esub>`
  have "num_of_big_int (word32_to_int o a) (\<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) (i + 1 - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (i + 1 - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
    num_of_big_int' c \<lfloor>c_first\<rfloor>\<^sub>\<nat> (i + 1 - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> +
    \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> =
    num_of_big_int (word32_to_int o a) (\<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
    num_of_big_int' c \<lfloor>c_first\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> +
    \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> +
    Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) *
      (\<lfloor>a1 (i + 1)\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub>)"
    by (simp add: diff_add_eq [symmetric] ring_distribs)
      (simp add: add.commute)
  also note inv
  also have "num_of_big_int (word32_to_int o a1) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * (\<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub>) +
    Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) *
      (\<lfloor>a1 (i + 1)\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub>) =
    num_of_big_int (word32_to_int o a1) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    Base ^ nat (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) *
      (\<lfloor>a1 (i + 1)\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>x\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>elts c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>))\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>y\<rfloor>\<^bsub>w32\<^esub> +
       \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub>)"
    by (simp add: ring_distribs)
  also note single
  finally show ?thesis using `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
    by (simp add: diff_add_eq [symmetric] nat_add_distrib ring_distribs fun_upd_comp base_eq)
      (simp add: o_def)
qed

why3_end

end
