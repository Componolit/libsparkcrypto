theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_41
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_41.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) e_first (e_last - e_first + 1)"

  from
    `(math_int_from_word w * math_int_from_word (of_int 2) ^ nat (j2 - s2 - 1) = _) = _`
    [simplified, symmetric]
  have "uint w * 2 ^ nat (j2 - s2 - 1) =
    (?e div 2 ^ nat (uint i - (j2 - 1)) -
     ?e div 2 ^ nat (uint i - (j2 - 1)) mod 2 ^ nat j2 mod 2 ^ nat (j2 - s2 - 1))
      mod 2 ^ nat j2"
    by simp
  also from `s2 < j2` `(math_int_of_int j2 \<le> math_int_from_word i + _) = _`
    `_ \<longrightarrow> natural_in_range s2`
  have "?e div 2 ^ nat (uint i - (j2 - 1)) -
    ?e div 2 ^ nat (uint i - (j2 - 1)) mod 2 ^ nat j2 mod 2 ^ nat (j2 - s2 - 1) =
    ?e div 2 ^ nat (uint i - s2) * 2 ^ nat (j2 - s2 - 1)"
    by (auto simp add: mod_mod_cancel le_imp_power_dvd
      mod_div_equality' [symmetric] zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric]
      natural_in_range_def)
  also from `s2 < j2` `_ \<longrightarrow> natural_in_range s2`
  have "?e div 2 ^ nat (uint i - s2) * 2 ^ nat (j2 - s2 - 1) mod 2 ^ nat j2 =
    ?e div 2 ^ nat (uint i - s2) mod 2 ^ nat (s2 + 1) * 2 ^ nat (j2 - s2 - 1)"
    by (simp add: mult_mod_left power_add [symmetric] nat_add_distrib [symmetric]
      natural_to_int_lower natural_in_range_def)
  finally show ?thesis
    by (simp add: t__content_def int__content_def)
qed

why3_end

end
