theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  from `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i3` `\<not> \<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i3 - 1`
  have "i3 = \<lfloor>a_first\<rfloor>\<^sub>\<nat>" by simp
  with
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `(if \<lfloor>elts b \<lfloor>j\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts a i3\<rfloor>\<^bsub>w32\<^esub> then True else False) \<noteq> True`
    `(if \<lfloor>elts a i3\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts b \<lfloor>j\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> then True else False) \<noteq> True`
    `j = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i3 - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)`
    `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
  have "num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> (1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)) =
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - \<lfloor>a_first\<rfloor>\<^sub>\<nat>))"
    by simp
  with `(num_of_big_int' a _ _ < num_of_big_int' b _ _) = _`
  show ?thesis by (simp add: add.commute)
qed

why3_end

end
