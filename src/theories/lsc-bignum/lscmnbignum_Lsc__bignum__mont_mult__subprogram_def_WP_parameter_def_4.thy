theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

lemma mod_cong: "a = b \<Longrightarrow> a mod m = b mod m"
  by simp

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  let ?a = "num_of_big_int (word32_to_int \<circ> a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?a' = "num_of_big_int (word32_to_int \<circ> a1) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?R = "Base ^ nat (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  note sub = `(num_of_big_int' (Array a _) _ _ - ?m = _) = _`
    [simplified base_eq, simplified]
  note invariant1 = `((num_of_big_int' (Array a _) _ _ + _) mod _ = _) = _`
  note invariant2 = `(num_of_big_int' (Array a _) _ _ + _ < 2 * _ - 1) = _`

  from `i1 = i2 + 1` `\<not> i1 \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `i2 \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "i2 = \<lfloor>a_last1\<rfloor>\<^sub>\<nat>" by simp

  have "?m < ?R" "?a' < ?R" by (simp_all add: num_of_lint_upper word32_to_int_upper')
  moreover from `_ = (if less _ _ _ _ _ \<noteq> _ then _ else _)`
    `(less _ _ _ _ _ = _) = _`
  have "?m \<le> ?a" by simp
  moreover from `\<lfloor>a_msw1\<rfloor>\<^bsub>w32\<^esub> = 0` invariant2 have "?a - ?m < ?m" by simp
  ultimately have "?a' = (?a - ?m) mod ?m"
    using sub [THEN mod_cong, of ?R]
    by (simp add: mod_pos_pos_trivial num_of_lint_lower word32_to_int_lower)
  with `\<lfloor>a_msw1\<rfloor>\<^bsub>w32\<^esub> = 0` `i2 = \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` invariant1
  show ?thesis
    by (simp add: diff_add_eq)
qed

why3_end

end
