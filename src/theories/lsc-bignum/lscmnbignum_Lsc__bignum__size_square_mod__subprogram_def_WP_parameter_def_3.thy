theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

lemma mod_eq:
  assumes "(0::int) \<le> x" and "x < m" and "m < r" and "r \<le> x * 2"
  shows "(x * 2) mod m = ((x * 2) mod r - m) mod r"
proof -
  have "(x * 2) mod m = (x * 2 - m) mod m"
    by simp
  also from `x < m` `m < r` `r \<le> x * 2`
  have "0 \<le> x * 2 - m" "x * 2 - m < m" by simp_all
  then have "(x * 2 - m) mod m = x * 2 - m"
    by (rule mod_pos_pos_trivial)
  also from `0 \<le> x * 2 - m` `x * 2 - m < m` `m < r`
  have "\<dots> = ((x * 2) mod r - m) mod r"
    by (simp add: mod_pos_pos_trivial)
  finally show ?thesis .
qed

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat> + 1"
  let ?R = "Base ^ nat ?l"
  let ?r = "num_of_big_int (word32_to_int o r2) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?l"

  from `(num_of_big_int' (Array r3 _) _ _ - _ = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>r_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat>)`
  have r_minus_m: "(num_of_big_int (word32_to_int o r3) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l - ?m) mod ?R =
    num_of_big_int (word32_to_int o r4) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l"
    by (simp add: mod_diff_right_eq [of _ "?R * num_of_bool carry"]
      num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial
      word32_to_int_lower word32_to_int_upper' base_eq)

  have "0 \<le> ?r" by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover from `(num_of_big_int' (Array r2 _) _ _ = _) = _`
    `(1 < num_of_big_int' m _ _) = _`
  have "?r < ?m" by simp
  moreover have "?m < ?R"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover from `(num_of_big_int' (Array r2 _) _ _ * 2 = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>r_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat>)`
  have "?R \<le> ?r * 2" by (simp add: num_of_lint_lower word32_to_int_lower base_eq)
  ultimately have "(?r * 2) mod ?m = ((?r * 2) mod ?R - ?m) mod ?R"
    by (rule mod_eq)
  also from `(num_of_big_int' (Array r2 _) _ _ * 2 = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>r_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>m_last\<rfloor>\<^sub>\<nat> - \<lfloor>m_first\<rfloor>\<^sub>\<nat>)`
  have "(?r * 2) mod ?R = num_of_big_int (word32_to_int o r3) \<lfloor>r_first1\<rfloor>\<^sub>\<nat> ?l"
    by (simp add: num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial
      word32_to_int_lower word32_to_int_upper' base_eq)
  also note r_minus_m
  finally show ?thesis using `(num_of_big_int' (Array r2 _) _ _ = _) = _` `0 \<le> j`
    by (simp add: nat_add_distrib mult_ac base_eq o_def)
qed

why3_end

end
