theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  from `a_first \<le> result1` `\<not> a_first \<le> result1 - 1`
  have "result1 = a_first" by simp
  with
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `(if BV32.ugt (elts a result1) (elts b j) then True else False) \<noteq> True`
    `(if BV32.ult (elts a result1) (elts b j) then True else False) \<noteq> True`
    `j = b_first + (result1 - a_first)`
    `a_first \<le> a_last`
  have "num_of_big_int' a a_first (1 + (a_last - a_first)) =
    num_of_big_int' b b_first (1 + (a_last - a_first))"
    by (simp add: BV32.ult_def BV32.ugt_def)
  with `(num_of_big_int' a _ _ < num_of_big_int' b _ _) = _`
  show ?thesis by (simp add: add.commute)
qed

why3_end

end
