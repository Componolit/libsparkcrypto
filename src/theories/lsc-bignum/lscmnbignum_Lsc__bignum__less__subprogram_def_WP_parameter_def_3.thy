theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_3
imports "../Less"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  let ?l' = "i - a_first"
  let ?l = "1 + (a_last - i)"
  let ?a' = "int_of_math_int (num_of_big_int' a a_first ?l')"
  let ?b' = "int_of_math_int (num_of_big_int' b b_first ?l')"
  let ?a = "int_of_math_int (num_of_big_int' a i ?l)"
  let ?b = "int_of_math_int (num_of_big_int' b (b_first + ?l') ?l)"
  let ?c = "Base ^ nat ?l'"
  have "0 \<le> ?a'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover have "?a' < ?c"
    by (simp add: num_of_lint_upper word32_to_int_upper')
  moreover have "0 \<le> ?b'"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  moreover from
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `_ = (if BV32.ult (elts a o1) (elts b _) then _ else _)`
    `mk_int__ref i = mk_int__ref o1` `o1 \<le> a_last`
  have "?a < ?b" by (simp add: word32_to_int_def BV32.ult_def)
  ultimately have "?a' + ?c * ?a < ?b' + ?c * ?b"
    by (rule msw_less)
  then have "int_of_math_int (num_of_big_int' a a_first (?l' + ?l)) <
    int_of_math_int (num_of_big_int' b b_first (?l' + ?l))"
    using `a_first \<le> o1` `o1 \<le> a_last`
      `mk_int__ref i = mk_int__ref o1` [simplified]
    by (simp only: num_of_lint_sum) simp
  then show ?thesis by (simp add: sign_simps)
qed

why3_end

end
