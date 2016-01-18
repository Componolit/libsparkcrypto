theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

lemma mod_eq':
  assumes "(x::int) < m" and "m < r" and "m \<le> x * 2"
  shows "(x * 2) mod m = (x * 2 - m) mod r"
proof -
  have "(x * 2) mod m = (x * 2 - m) mod m"
    by simp
  also from `x < m` `m \<le> x * 2`
  have "0 \<le> x * 2 - m" "x * 2 - m < m" by simp_all
  then have "(x * 2 - m) mod m = x * 2 - m"
    by (rule mod_pos_pos_trivial)
  also from `0 \<le> x * 2 - m` `x * 2 - m < m` `m < r`
  have "\<dots> = (x * 2 - m) mod r"
    by (simp add: mod_pos_pos_trivial)
  finally show ?thesis .
qed

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "m_last - m_first + 1"
  let ?R = "Base ^ nat ?l"
  let ?r = "num_of_big_int (word32_to_int o r2) r_first ?l"
  let ?m = "int_of_math_int (num_of_big_int' m m_first ?l)"

  from `(num_of_big_int' (Array r3 _) _ _ - _ = _) = _`
  have r_minus_m: "(num_of_big_int (word32_to_int o r3) r_first ?l - ?m) mod ?R =
    num_of_big_int (word32_to_int o r4) r_first ?l"
    by (simp add: mod_diff_right_eq [of _ "?R * num_of_bool carry"]
      num_of_lint_lower num_of_lint_upper mod_pos_pos_trivial
      word32_to_int_lower word32_to_int_upper' base_eq)

  from `carry1 \<noteq> True`
    `(num_of_big_int' (Array r2 _) _ _ * _ = _) = _`
  have r2: "num_of_big_int (word32_to_int o r3) r_first ?l = ?r * 2"
    by simp

  from `(num_of_big_int' (Array r2 _) _ _ = _) = _`
    `(_ < num_of_big_int' m _ _) = _`
  have "?r < ?m" by simp
  moreover have "?m < ?R"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover from r2
    `_ = (if WP_parameter_def.less _ _ _ _ _ \<noteq> _ then _ else _)`
    `(WP_parameter_def.less _ _ _ _ _ = _) = _`
  have "?m \<le> ?r * 2" by simp
  ultimately have "(?r * 2) mod ?m = (?r * 2 - ?m) mod ?R"
    by (rule mod_eq')
  then show ?thesis using
    `(num_of_big_int' (Array r2 _) _ _ = _) = _` `0 \<le> j` r_minus_m r2
    by (simp add: nat_add_distrib mult_ac)
qed

why3_end

end
