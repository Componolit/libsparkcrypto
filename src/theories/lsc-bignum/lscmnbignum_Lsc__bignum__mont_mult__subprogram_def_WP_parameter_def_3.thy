theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `i1 = i2 + 1` `\<not> i1 \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `i2 \<le> \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "i2 = \<lfloor>a_last1\<rfloor>\<^sub>\<nat>" by simp
  with `(if less _ _ _ _ _ \<noteq> _ then _ else _) \<noteq> _`
    `(less _ _ _ _ _ = _) = _` `\<lfloor>a_msw1\<rfloor>\<^bsub>w32\<^esub> = 0`
    `((num_of_big_int' (Array a _) _ _ + _) mod _ = _) = _`
    `a1 = a`
  show ?thesis
    by (simp add: base_eq mod_pos_pos_trivial
      num_of_lint_lower word32_to_int_lower diff_add_eq)
qed

why3_end

end
