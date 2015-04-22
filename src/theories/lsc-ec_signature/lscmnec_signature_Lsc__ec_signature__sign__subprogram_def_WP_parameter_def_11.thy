theory lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_11
imports "../LibSPARKcrypto"
begin

why3_open "lscmnec_signature_Lsc__ec_signature__sign__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
proof -
  have "0 \<le> num_of_big_int (word32_to_int \<circ> sign2) \<lfloor>sign2_first1\<rfloor>\<^sub>\<nat>
    (\<lfloor>sign1_last1\<rfloor>\<^sub>\<nat> - \<lfloor>sign1_first1\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: num_of_lint_lower word32_to_int_lower)
  with
    `_ = (if is_zero (Array sign2 _) _ _ \<noteq> True then _ else _)`
    `(is_zero (Array sign2 _) _ _ = True) = _`
    `l = o1` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>sign1_last1\<rfloor>\<^sub>\<nat> - \<lfloor>sign1_first1\<rfloor>\<^sub>\<nat>`
  show ?thesis by simp
qed

why3_end

end
