theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_5
imports "../LibSPARKcrypto"
begin

lemma mod_cong: "a = b \<Longrightarrow> a mod m = b mod m"
  by simp

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
proof -
  let ?a = "num_of_big_int (word32_to_int \<circ> a1) a_first (a_last - a_first + 1)"
  let ?a' = "num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first (a_last - a_first + 1)"
  let ?R = "Base ^ nat (a_last - a_first + 1)"
  note sub = `(num_of_big_int' (Array a1 _) _ _ - num_of_big_int' m _ _ = _) = _`
    [simplified base_eq, simplified]
  note invariant1 = `((num_of_big_int' (Array a1 _) _ _ + _) mod _ = _) = _`
  note invariant2 = `(num_of_big_int' (Array a1 _) _ _ + _ < _ * _ - _) = _`

  have "?m < ?R" by (simp add: num_of_lint_upper word32_to_int_upper')
  have "0 \<le> ?m" "0 \<le> ?a" by (simp_all add: num_of_lint_lower word32_to_int_lower)

  from sub [THEN mod_cong, of ?R]
    have "?a' = (?a + ?R * \<lfloor>a_msw2\<rfloor>\<^sub>s - ?m) mod ?R"
      by (simp add: mod_pos_pos_trivial num_of_lint_lower word32_to_int_lower
        num_of_lint_upper word32_to_int_upper')
  also from `a_msw2 \<noteq> of_int 0` [simplified word_uint_eq_iff, simplified, folded word32_to_int_def]
    word32_to_int_lower [of a_msw2]
  have "1 \<le> \<lfloor>a_msw2\<rfloor>\<^sub>s" by simp
  with `?m < ?R` have "?m * 1 < ?R * \<lfloor>a_msw2\<rfloor>\<^sub>s" using `0 \<le> ?m`
    by (rule mult_less_le_imp_less) simp_all
  with invariant2 `0 \<le> ?a` `0 \<le> ?m` `?m < ?R`
  have "(?a + ?R * \<lfloor>a_msw2\<rfloor>\<^sub>s - ?m) mod ?R = (?a + ?R * \<lfloor>a_msw2\<rfloor>\<^sub>s - ?m) mod ?m"
    by (simp add: mod_pos_pos_trivial base_eq word32_to_int_def del: minus_mod_self2)
  finally show ?thesis using invariant1
    by (simp add: diff_add_eq base_eq word32_to_int_def)
qed

why3_end

end
