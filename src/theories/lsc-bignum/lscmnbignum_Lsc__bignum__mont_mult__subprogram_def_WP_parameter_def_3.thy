theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
  using
    `(if less _ _ _ _ _ \<noteq> _ then _ else _) \<noteq> _`
    `(less _ _ _ _ _ = _) = _`
    `((num_of_big_int' (Array a _) _ _ + _) mod _ = _) = _`
  by (simp add: base_eq mod_pos_pos_trivial
    num_of_lint_lower word32_to_int_lower diff_add_eq)

why3_end

end
