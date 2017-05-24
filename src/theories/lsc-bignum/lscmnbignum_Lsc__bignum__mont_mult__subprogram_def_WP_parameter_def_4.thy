theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

lemma mod_cong: "a = b \<Longrightarrow> a mod m = b mod m"
  by simp

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_4.xml"

abbreviation F where
  "F x \<equiv> map__content (mk_map__ref x)"

abbreviation G where
  "G x \<equiv> t__content (mk_t__ref x)"

lemma [simp]: "F x = x"
  by (simp add: map__content_def)

lemma [simp]: "G x = x"
  by (simp add: t__content_def)

why3_vc WP_parameter_def
proof -
  let ?a = "num_of_big_int (word32_to_int \<circ> a1) a_first (a_last - a_first + 1)"
  let ?a' = "num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first (a_last - a_first + 1)"
  let ?R = "Base ^ nat (a_last - a_first + 1)"
  note sub = `(num_of_big_int' (Array (F a1) _) _ _ - num_of_big_int' m _ _ = _) = _`
    [simplified base_eq, simplified]
  note invariant1 = `((num_of_big_int' (Array a1 _) _ _ + _) mod _ = _) = _`
    [simplified `G a_msw1 = of_int 0` [simplified]]
  note invariant2 = `(num_of_big_int' (Array a1 _) _ _ + _ < _ * _ - _) = _`
    [simplified `G a_msw1 = of_int 0` [simplified]]

  have "?m < ?R" "?a' < ?R" by (simp_all add: num_of_lint_upper word32_to_int_upper')
  moreover from `(if less _ _ _ _ _ \<noteq> _ then _ else _) = _`
    `(less _ _ _ _ _ = _) = _`
  have "?m \<le> ?a" by simp
  moreover from invariant2 have "?a - ?m < ?m" by simp
  ultimately have "?a' = (?a - ?m) mod ?m"
    using sub [THEN mod_cong, of ?R]
    by (simp add: mod_pos_pos_trivial num_of_lint_lower word32_to_int_lower)
  with invariant1
  show ?thesis
    by (simp add: diff_add_eq)
qed

why3_end

end
