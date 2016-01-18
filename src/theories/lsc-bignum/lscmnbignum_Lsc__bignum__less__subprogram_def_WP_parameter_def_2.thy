theory lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__less__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  from `o1 \<le> a_last`
    `(num_of_big_int' a _ _ = num_of_big_int' b _ _) = _`
    `(if BV32.ult (elts a o1) (elts b (b_first + (o1 - a_first))) then _ else _) \<noteq> _`
    `(if BV32.ugt (elts a o1) (elts b (b_first + (o1 - a_first))) then _ else _) \<noteq> _`
  have "num_of_big_int' a o1 (1 + (a_last - o1)) =
    num_of_big_int' b (b_first + (o1 - a_first)) (1 + (a_last - o1))"
    by (simp add: BV32.ult_def BV32.ugt_def)
  then show ?thesis by (simp add: sign_simps)
qed

why3_end

end
