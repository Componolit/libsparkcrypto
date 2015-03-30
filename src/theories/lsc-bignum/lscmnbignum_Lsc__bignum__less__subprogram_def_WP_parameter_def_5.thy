theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_5
imports "../Less"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
proof -
  let ?l' = "i3 - \<lfloor>a_first\<rfloor>\<^sub>\<nat>"
  let ?l = "1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - i3)"
  let ?a' = "num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> ?l'"
  let ?b' = "num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> ?l'"
  let ?a = "num_of_big_int' a i3 ?l"
  let ?b = "num_of_big_int' b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + ?l') ?l"
  let ?c = "Base ^ nat ?l'"
  have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "?b' < ?c"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover from
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `_ = (if \<lfloor>elts b \<lfloor>j\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts a i3\<rfloor>\<^bsub>w32\<^esub> then _ else _)`
    `i3 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
    `j = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i3 - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)`
  have "?b < ?a" by simp
  ultimately have "?b' + ?c * ?b < ?a' + ?c * ?a"
    by (rule msw_less)
  then have "num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (?l' + ?l) <
    num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> (?l' + ?l)"
    using `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i3` `i3 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
    by (simp only: num_of_lint_sum) simp
  with `(num_of_big_int' a _ _ < num_of_big_int' b _ _) = _`
  show ?thesis by (simp add: sign_simps)
qed

why3_end

end
