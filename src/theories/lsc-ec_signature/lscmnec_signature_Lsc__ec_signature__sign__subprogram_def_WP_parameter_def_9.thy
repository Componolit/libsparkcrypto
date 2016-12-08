theory lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_9
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_9.xml"

why3_vc WP_parameter_def
proof -
  have "0 \<le> num_of_big_int (word32_to_int \<circ> sign1) sign1_first
    (sign1_last - sign1_first + 1)"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  with
    `(if is_zero (Array sign1 _) _ _ \<noteq> True then _ else _) = _`
    `(is_zero (Array sign1 _) _ _ = True) = _`
  show ?thesis by simp
qed

why3_end

end
