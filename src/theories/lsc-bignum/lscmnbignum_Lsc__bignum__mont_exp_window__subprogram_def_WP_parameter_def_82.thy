theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_82
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_82.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"

  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux1 _) _ _ = _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  have "num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L =
    num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L ^
      nat (num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) div
        2 ^ nat (\<lfloor>i2\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>s1\<rfloor>\<^sub>\<nat> + 1)) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: power_mult_distrib mult.assoc base_eq)
  with Base_inv `(\<lfloor>s1\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i2\<rfloor>\<^bsub>w64\<^esub> + 1) = _`
    `_ = (if \<lfloor>i2\<rfloor>\<^bsub>w64\<^esub> < \<lfloor>o1\<rfloor>\<^bsub>w64\<^esub> then _ else _)` `\<lfloor>o1\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>s1\<rfloor>\<^sub>\<nat>`
  show ?thesis by simp
qed

why3_end

end
