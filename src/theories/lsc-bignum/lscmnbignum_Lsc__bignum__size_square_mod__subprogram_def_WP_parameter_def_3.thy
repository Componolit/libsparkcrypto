theory lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__size_square_mod__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  let ?l = "m_last - m_first + 1"
  let ?r = "num_of_big_int (word32_to_int o r2) r_first ?l"
  let ?m = "int_of_math_int (num_of_big_int' m m_first ?l)"

  from `carry \<noteq> True`
    `(num_of_big_int' (Array r2 _) _ _ * _ = _) = _`
    `(if WP_parameter_def.less _ _ _ _ _ \<noteq> _ then _ else _) \<noteq> _`
    `(WP_parameter_def.less _ _ _ _ _ = _) = _`
  have "num_of_big_int (word32_to_int o r3) r_first ?l = (?r * 2) mod ?m"
    by (simp add: num_of_lint_lower word32_to_int_lower mod_pos_pos_trivial)
  then show ?thesis using `(num_of_big_int' (Array r2 _) _ _ = _) = _` `0 \<le> j`
    by (simp add: nat_add_distrib mult_ac)
qed

why3_end

end
