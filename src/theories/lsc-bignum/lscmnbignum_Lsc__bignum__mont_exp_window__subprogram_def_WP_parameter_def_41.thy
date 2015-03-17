theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_41
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_41.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"

  from
    `(if (if \<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat> then _ else _) \<noteq> _ then _ else _) \<noteq> _`
    `\<lfloor>o8\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>j\<rfloor>\<^sub>\<nat>`
  have "\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat>" "\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>"
    by simp_all

  from
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
    `\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) emod _ * 32 emod _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    natural_to_int_lower [of j]
  have i: "\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat> < 32 * (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: mod_pos_pos_trivial emod_def)

  from `\<lfloor>s\<rfloor>\<^sub>\<nat> < \<lfloor>j\<rfloor>\<^sub>\<nat>`
  have "(2::int) ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>) = 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) * 2 ^ 1"
    by (simp add: power_add [symmetric] del: power.simps)
  then have "\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>) = \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) * 2"
    by simp
  also note `(\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat>) = _` [simplified]
  also from `\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>`
  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> * 2 =
    (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2) mod (2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> + 1))"
    by (simp add:
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute
      num_of_lint_lower word32_to_int_lower natural_to_int_lower)
  also from i `\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>`
    `bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> ((\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>o7\<rfloor>\<^bsub>w64\<^esub>) emod _) \<noteq> _`
    `(bit_set e \<lfloor>e_first\<rfloor>\<^sub>\<nat> ((\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>o7\<rfloor>\<^bsub>w64\<^esub>) emod _) = _) = _`
    `\<lfloor>o7\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>j\<rfloor>\<^sub>\<nat>`
    word64_to_int_upper [of i]
    natural_to_int_lower [of j]
  have "?e AND 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) = 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      emod_def ediv_def mod_def mod_pos_pos_trivial
      word32_to_int_lower word32_to_int_upper'
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2 =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2 + ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis using `\<lfloor>o6\<rfloor>\<^sub>\<nat> = \<lfloor>j\<rfloor>\<^sub>\<nat> + 1`
    by simp
qed

why3_end

end
