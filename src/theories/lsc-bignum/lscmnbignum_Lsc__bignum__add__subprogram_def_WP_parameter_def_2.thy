theory lscmnbignum_Lsc__bignum__add__subprogram_def_WP_parameter_def_2
imports "../Add"
begin

why3_open "lscmnbignum_Lsc__bignum__add__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
  using
    `(num_of_big_int' b _ _ + num_of_big_int' c _ _ = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = _`
    `(\<lfloor>word_of_boolean carry\<rfloor>\<^bsub>w32\<^esub> = num_of_bool carry) = _`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
  by (simp add: diff_add_eq [symmetric] nat_add_distrib
    add_carry div_mod_eq ring_distribs base_eq emod_def fun_upd_comp
    word32_to_int_lower word32_to_int_upper')

why3_end

end
