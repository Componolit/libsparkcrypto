theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_74
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_74.xml"

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

  from `h3 \<le> \<lfloor>r224b\<rfloor>\<^sub>\<nat>` `h2 = h3 + 1` `\<not> h2 \<le> \<lfloor>r224b\<rfloor>\<^sub>\<nat>`
  have "h3 = \<lfloor>r224b\<rfloor>\<^sub>\<nat>" by simp

  from
    `\<forall>k. \<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> k \<and> k \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int> \<longrightarrow> _`
    `\<lfloor>aux3_first\<rfloor>\<^sub>\<int> \<le> \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat>`
    `\<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> + (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) \<le> \<lfloor>aux3_last\<rfloor>\<^sub>\<int>`
  have "num_of_big_int (word32_to_int o aux32) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L =
    num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  also from
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `\<lfloor>o3\<rfloor>\<^sub>\<nat> = \<lfloor>shr32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> 1\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>shr32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> 1\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> ediv 2 ^ nat 1`
    `(\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> = _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  have "num_of_big_int (word32_to_int o a) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> ?L =
    num_of_big_int (word32_to_int \<circ> aux33) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L *
    num_of_big_int (word32_to_int \<circ> aux41)
      (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod
       2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2 * ?L) ?L * minv ?m Base ^ nat ?L mod ?m"
    by (simp add: ediv_def base_eq)
  also note `(num_of_big_int' (Array aux33 _) _ _ = _) = _`
    [simplified `h3 = \<lfloor>r224b\<rfloor>\<^sub>\<nat>` `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>` base_eq, simplified]
  also {
    have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> < 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat>"
      by simp
    also from `\<lfloor>r224b\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat> + 1`
    have "(2::int) ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> \<le> 2 ^ nat (\<lfloor>k\<rfloor>\<^sub>\<nat> + 1)"
      by simp
    then have "(2::int) ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> \<le> 2 * 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>"
      by (simp add: nat_add_distrib natural_to_int_lower)
    finally have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod
      2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2 < 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat>"
      by simp
    with
      `\<forall>n. 0 \<le> n \<and> n \<le> 2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1 \<longrightarrow> (num_of_big_int' (Array aux41 _) _ _ = _) = _`
      `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
    have "num_of_big_int (word32_to_int o aux41)
      (\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2 * ?L) ?L =
      ?x ^ nat (2 * (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2) + 1) *
      ?R mod ?m"
      by (simp add: pos_imp_zdiv_nonneg_iff base_eq)
  } also from
    `WP_parameter_def.mod \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> 2 = 1`
    `(\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> = _) = _`
  have "2 * (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2) + 1 =
    2 * (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2) +
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> mod 2"
    by (simp add: num_of_lint_lower word32_to_int_lower mod_def emod_def)
  also have "\<dots> = ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat>"
    by simp
  also from `0 \<le> \<lfloor>r224b\<rfloor>\<^sub>\<nat>` `(\<lfloor>r224b\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> + 1) = _`
  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> + 1) =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) div 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat>"
    by (simp add: zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric])
  also have
    "?x ^ nat (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) div 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> * 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat>) * ?R mod ?m *
     (?x ^ nat (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat>) * ?R mod ?m) *
     minv ?m Base ^ nat ?L mod ?m =
     ?x ^ nat (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1))) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      pos_imp_zdiv_nonneg_iff num_of_lint_lower mult_nonneg_nonneg
      mod_div_equality word32_to_int_lower)
  finally show ?thesis
    by (simp add: num_of_lint_lower word32_to_int_lower sign_simps base_eq
      `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>` o_def)
qed

why3_end

end
