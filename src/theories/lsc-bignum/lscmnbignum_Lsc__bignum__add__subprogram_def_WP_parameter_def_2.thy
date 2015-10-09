theory lscmnbignum_Lsc__bignum__add__subprogram_def_WP_parameter_def_2
imports "../Add"
begin

why3_open "lscmnbignum_Lsc__bignum__add__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' b _ _ + num_of_big_int' c _ _ = _) = _`
    `o1 = _`
    `(math_int_from_word (word_of_boolean result3) = num_of_bool result3) = _`
    `a_first \<le> i1`
  by (simp add: diff_add_eq [symmetric] nat_add_distrib
    add_carry div_mod_eq ring_distribs base_eq emod_def fun_upd_comp
    BV32.ult_def uint_word_ariths word_uint_eq_iff
    uint_lt [where 'a=32, simplified] word32_to_int_def)

why3_end

end
