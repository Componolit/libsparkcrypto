theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_10
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_10.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?r = "num_of_big_int' r \<lfloor>r_first\<rfloor>\<^sub>\<nat> ?L"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<forall>k. \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> + \<lfloor>o1\<rfloor>\<^sub>\<nat> \<longrightarrow> \<lfloor>aux1 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  have one: "num_of_big_int ((word32_to_int \<circ> aux1)(\<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> := 1))
    \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> ?L = 1"
    by (simp add: num_of_lint_all0)

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from `(?r = _) = _`
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals] base_eq)
      (simp add: power_mult_distrib mult.assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  with
    `(num_of_big_int' (Array aux3 _) _ _ = _) = _`
    `\<lfloor>o1\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>` `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = 1` one
  show ?thesis
    by (simp add: base_eq fun_upd_comp)
qed

why3_end

end
