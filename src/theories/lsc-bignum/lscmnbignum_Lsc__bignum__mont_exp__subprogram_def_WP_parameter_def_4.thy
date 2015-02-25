theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_4
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
  using `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
  by (simp add: div_pos_pos_trivial word32_to_int_lower word32_to_int_upper')

why3_end

end
