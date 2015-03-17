theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_75
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_75.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?e = "num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"
  let ?x = "num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod
      [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
    `\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) emod _ * 32 emod _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
  have i: "\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < 32 * (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: mod_pos_pos_trivial emod_def)

  from
    `\<forall>k. \<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int o aux32) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L =
    num_of_big_int (word32_to_int o a2) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  with
    `(num_of_big_int' (Array a2 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux31 _) _ _ = _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  have "num_of_big_int (word32_to_int o aux32) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L =
    ?x ^ nat ((?e div 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> div 2) * 2) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      num_of_lint_lower pos_imp_zdiv_nonneg_iff base_eq word32_to_int_lower)
      (simp add: nat_add_distrib zdiv_zmult2_eq [symmetric] mult_ac word64_to_int_lower)
  also have "(?e div 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> div 2) * 2 =
    ?e div 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - ?e div 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> mod 2"
    by (simp add: mod_div_equality')
  also from i
    `bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> \<noteq> True`
    `(bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> = True) = _`
  have "?e AND 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> = 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      word32_to_int_lower word32_to_int_upper' word64_to_int_lower
      ediv_def emod_def mod_def
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> mod 2 = 0"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>` `\<lfloor>o3\<rfloor>\<^sub>\<nat> = 1`
    by (simp add: base_eq o_def)
qed

why3_end

end
