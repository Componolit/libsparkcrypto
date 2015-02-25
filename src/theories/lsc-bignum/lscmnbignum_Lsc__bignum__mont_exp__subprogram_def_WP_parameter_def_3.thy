theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_3.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?x = "num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L"
  let ?r = "num_of_big_int' r \<lfloor>r_first\<rfloor>\<^sub>\<nat> ?L"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<forall>k. \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> \<le> k \<and> k \<le> \<lfloor>aux1_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) \<longrightarrow>
    \<lfloor>aux1 k\<rfloor>\<^bsub>w32\<^esub> = 0`
    `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `\<lfloor>o1\<rfloor>\<^bsub>w32\<^esub> = 1`
  show one: ?C1 by (simp add: num_of_lint_all0 fun_upd_comp)

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from `(?r = _) = _` [unfolded base_eq]
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals])
      (simp add: power_mult_distrib mult.assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  from `(num_of_big_int' (Array aux2 _) _ _ = _) = _`
  have "num_of_big_int (word32_to_int o aux2) \<lfloor>aux2_first1\<rfloor>\<^sub>\<nat> ?L =
    ?x * (?r * minv ?m Base ^ nat ?L mod ?m) mod ?m"
    by (simp add: mult.assoc base_eq)
  with R show ?C2 by (simp add: base_eq)

  from `(num_of_big_int' (Array aux3 _) _ _ = _) = _` one R
  show ?C3 by (simp add: base_eq)
qed

why3_end

end
