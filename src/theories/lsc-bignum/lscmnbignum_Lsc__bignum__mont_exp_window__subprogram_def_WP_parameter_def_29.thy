theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_29
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_29.xml"

why3_vc WP_parameter_def
proof -
  from
    `natural_in_range e_first`
    `natural_in_range e_last`
    `e_first \<le> e_last`
  have "int_of_math_int
    (math_int_from_word ((of_int (e_last - e_first) + of_int 1) * of_int 32 - of_int 1 :: 64 word) +
     math_int_from_word (of_int 1 :: 32 word)) =
    (e_last - e_first + 1) * 32"
    by (simp add: uint_word_ariths word_of_int uint_word_of_int natural_in_range_def
      mod_pos_pos_trivial)
  with
    `(num_of_big_int' (Array aux3 _) _ _ = _) = _`
    `e_first \<le> e_last`
  show ?thesis
    by (simp only: nat_mult_distrib base_eq)
      (simp add: power_mult mult.commute [of _ 32]
         num_of_lint_lower num_of_lint_upper word32_to_int_lower word32_to_int_upper'
         div_pos_pos_trivial del: num_of_lint_sum)
qed

why3_end

end
