theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `i \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `(if \<lfloor>elts a i\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts b \<lfloor>o1\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> then _ else _) \<noteq> _`
    `(if \<lfloor>elts b \<lfloor>o1\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts a i\<rfloor>\<^bsub>w32\<^esub> then _ else _) \<noteq> _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)`
  have "num_of_big_int' a i (1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - i)) =
    num_of_big_int' b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)) (1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - i))"
    by simp
  then show ?thesis by (simp add: sign_simps)
qed

why3_end

end
