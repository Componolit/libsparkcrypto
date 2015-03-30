theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_3
imports "../Less"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  let ?l' = "i - \<lfloor>a_first\<rfloor>\<^sub>\<nat>"
  let ?l = "1 + (\<lfloor>a_last\<rfloor>\<^sub>\<nat> - i)"
  let ?a' = "num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> ?l'"
  let ?b' = "num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> ?l'"
  let ?a = "num_of_big_int' a i ?l"
  let ?b = "num_of_big_int' b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + ?l') ?l"
  let ?c = "Base ^ nat ?l'"
  have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "?a' < ?c"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover from
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `_ = (if \<lfloor>elts a i2\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts b \<lfloor>j\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> then _ else _)`
    `mk_ref i = mk_ref i2` `i2 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
    `j = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>b_first\<rfloor>\<^sub>\<nat> + (i2 - \<lfloor>a_first\<rfloor>\<^sub>\<nat>)`
  have "?a < ?b" by simp
  ultimately have "?a' + ?c * ?a < ?b' + ?c * ?b"
    by (rule msw_less)
  then have "num_of_big_int' a \<lfloor>a_first\<rfloor>\<^sub>\<nat> (?l' + ?l) <
    num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (?l' + ?l)"
    using `\<lfloor>a_first\<rfloor>\<^sub>\<nat> \<le> i2` `i2 \<le> \<lfloor>a_last\<rfloor>\<^sub>\<nat>`
      `mk_ref i = mk_ref i2` [simplified]
    by (simp only: num_of_lint_sum) simp
  then show ?thesis by (simp add: sign_simps)
qed

why3_end

end
