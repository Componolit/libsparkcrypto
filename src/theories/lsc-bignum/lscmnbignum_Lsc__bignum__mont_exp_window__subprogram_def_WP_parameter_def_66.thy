theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_66
imports "../LibSPARKcrypto"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_66.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?e = "num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"

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
  with `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>r224b\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>r224b\<rfloor>\<^sub>\<nat> div 2 * ?L \<le>
    (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> - 1) * ?L"
    by simp
  with
    `\<lfloor>aux4_first1\<rfloor>\<^sub>\<nat> + (2 ^ nat \<lfloor>k\<rfloor>\<^sub>\<nat> * ?L - 1) \<le> \<lfloor>aux4_last\<rfloor>\<^sub>\<int>`
    `\<lfloor>o7\<rfloor>\<^sub>\<nat> = \<lfloor>shr32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> 1\<rfloor>\<^bsub>w32\<^esub>`
    `\<lfloor>shr32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> 1\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> ediv 2 ^ nat 1`
    `(\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> = _) = _`
    `\<lfloor>l\<rfloor>\<^sub>\<nat> = \<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>`
  show ?thesis by (simp add: left_diff_distrib mk_bounds_snd ediv_def)
qed

why3_end

end
