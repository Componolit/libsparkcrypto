theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_42
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_42.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"

  from
    `(if (if \<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat> then _ else _) \<noteq> _ then _ else _) \<noteq> _`
    `\<lfloor>o9\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>j\<rfloor>\<^sub>\<nat>`
  have "\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat>" "\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>"
    by simp_all

  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> < 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat>"
    by simp
  also from `\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>k\<rfloor>\<^sub>\<nat>` `\<lfloor>k\<rfloor>\<^sub>\<nat> \<le> 30`
  have "nat \<lfloor>j\<rfloor>\<^sub>\<nat> \<le> 30" by simp
  then have "(2::int) ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> \<le> 2 ^ 30"
    by (rule power_increasing) simp
  finally have e: "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> * 2 < Base"
    by simp

  from
    natural_to_int_lower [of e_first]
    natural_to_int_upper [of e_last]
    `\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> < (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1) emod _ * 32 emod _`
    `\<lfloor>e_first\<rfloor>\<^sub>\<nat> \<le> \<lfloor>e_last\<rfloor>\<^sub>\<nat>`
    natural_to_int_lower [of j]
  have i: "\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat> < 32 * (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"
    by (simp add: mod_pos_pos_trivial emod_def)

  from `\<lfloor>shl32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>) emod Base`
  have "(\<lfloor>shl32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> OR 1) =
    \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>) mod Base OR 1"
    by (simp add: emod_def)
  also from `\<lfloor>s\<rfloor>\<^sub>\<nat> < \<lfloor>j\<rfloor>\<^sub>\<nat>`
  have "(2::int) ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>) = 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) * 2 ^ 1"
    by (simp add: power_add [symmetric] del: power.simps)
  also from
    `(\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) = _) = _`
  have "\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * (2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat> - 1) * 2 ^ 1) =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> * 2"
    by (simp add: num_of_lint_lower)
  also from e have "\<dots> mod Base OR 1 =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j\<rfloor>\<^sub>\<nat> * 2 + 1"
    by (simp add: mod_pos_pos_trivial OR_plus1)
  also from `\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>` have "\<dots> =
    (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2 + 1) mod (2 ^ nat (\<lfloor>j\<rfloor>\<^sub>\<nat> + 1))"
    by (simp add: natural_to_int_lower mod_mult_add
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute [of 2])
  also from i `\<lfloor>j\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub>`
    `\<lfloor>elts e (\<lfloor>e_first\<rfloor>\<^sub>\<nat> + (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>o8\<rfloor>\<^bsub>w64\<^esub>) emod _ ediv 32)\<rfloor>\<^bsub>w32\<^esub> AND
     2 ^ nat (WP_parameter_def.mod ((\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>o8\<rfloor>\<^bsub>w64\<^esub>) emod _) 32) \<noteq> 0`
    `\<lfloor>o8\<rfloor>\<^bsub>w64\<^esub> = \<lfloor>j\<rfloor>\<^sub>\<nat>`
    word64_to_int_upper [of i]
    natural_to_int_lower [of j]
  have "?e AND 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) \<noteq> 0"
    by (simp add: num_of_lint_AND_32 zdiv_int nat_mod_distrib
      emod_def ediv_def mod_def mod_pos_pos_trivial
      word32_to_int_lower word32_to_int_upper'
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2 + 1 =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) div 2 * 2 + ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>j\<rfloor>\<^sub>\<nat>) mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using
      `\<lfloor>o7\<rfloor>\<^bsub>w32\<^esub> = \<lfloor>shl32 \<lfloor>w\<rfloor>\<^bsub>w32\<^esub> (\<lfloor>j\<rfloor>\<^sub>\<nat> - \<lfloor>s\<rfloor>\<^sub>\<nat>)\<rfloor>\<^bsub>w32\<^esub> OR 1`
      `\<lfloor>o6\<rfloor>\<^sub>\<nat> = \<lfloor>j\<rfloor>\<^sub>\<nat> + 1`
    by simp
qed

why3_end

end
