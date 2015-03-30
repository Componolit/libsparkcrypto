theory lscmnbignum_Lsc__bignum__sub__subprogram_def_WP_parameter_def_3
imports "../Sub"
begin

why3_open "lscmnbignum_Lsc__bignum__sub__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  from `True = _`
  have eq: "num_of_bool carry = num_of_bool
    (\<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + \<lfloor>o2\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> < \<lfloor>elts c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + \<lfloor>o2\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> \<or>
     \<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + \<lfloor>o2\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>elts c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + \<lfloor>o2\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> \<and> carry)"
    by simp
  from
    `(num_of_big_int' b _ _ - num_of_big_int' c _ _= _) = _`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
    `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = _`
    `\<lfloor>o2\<rfloor>\<^sub>\<nat> = i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    `(\<lfloor>word_of_boolean carry\<rfloor>\<^bsub>w32\<^esub> = num_of_bool carry) = _`
  show ?thesis
    by (simp (no_asm_simp) only: eq)
      (simp add: diff_add_eq [symmetric] nat_add_distrib
       sub_carry [of _ Base] div_mod_eq ring_distribs base_eq
       word32_to_int_lower word32_to_int_upper' emod_def fun_upd_comp)
qed

why3_end

end
