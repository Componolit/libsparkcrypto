theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_5
imports "../Less"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_5.xml"

why3_vc WP_parameter_def
proof -
  let ?l' = "i3 - a_first"
  let ?l = "1 + (a_last - i3)"
  let ?a' = "int_of_math_int (num_of_big_int' a a_first ?l')"
  let ?b' = "int_of_math_int (num_of_big_int' b b_first ?l')"
  let ?a = "int_of_math_int (num_of_big_int' a i3 ?l)"
  let ?b = "int_of_math_int (num_of_big_int' b (b_first + ?l') ?l)"
  let ?c = "Base ^ nat ?l'"
  have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "?b' < ?c"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover from
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `_ = (if BV32.ugt (elts a i3) (elts b j) then _ else _)`
    `i3 \<le> a_last`
    `j = b_first + (i3 - a_first)`
  have "?b < ?a" by (simp add: word32_to_int_def BV32.ugt_def)
  ultimately have "?b' + ?c * ?b < ?a' + ?c * ?a"
    by (rule msw_less)
  then have "num_of_big_int' b b_first (?l' + ?l) <
    num_of_big_int' a a_first (?l' + ?l)"
    using `a_first \<le> i3` `i3 \<le> a_last`
    by (simp only: num_of_lint_sum) simp
  with `(num_of_big_int' a _ _ < num_of_big_int' b _ _) = _`
  show ?thesis by (simp add: sign_simps)
qed

why3_end

end
