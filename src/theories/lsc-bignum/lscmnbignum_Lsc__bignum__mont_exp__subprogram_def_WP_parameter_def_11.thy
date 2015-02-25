theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_11
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?x = "num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L"
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `mk_ref aux31 = mk_ref aux32`
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux1 _) _ _ = _) = _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    `i1 = i2 - 1` `\<not> \<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> i1` `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> i2`
    `j2 = j3 - 1` `\<not> 0 \<le> j2` `0 \<le> j3`
  have "num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L =
    ?x ^ nat (num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (1 + (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat>))) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: power_mult_distrib [symmetric] mult.assoc base_eq)
      (simp add: add.commute mult.commute)
  with Base_inv show ?thesis by (simp add: add.commute)
qed

why3_end

end
