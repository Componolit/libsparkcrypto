theory lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_46
imports "../Mont_Mult_Aux"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_exp_window__subprogram_def_WP_parameter_def_46.xml"

why3_vc WP_parameter_def
proof -
  let ?e = "num_of_big_int' e \<lfloor>e_first\<rfloor>\<^sub>\<nat> (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - \<lfloor>e_first\<rfloor>\<^sub>\<nat> + 1)"

  from
    `(\<lfloor>w1\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1) = ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j1\<rfloor>\<^sub>\<nat> - 1)) mod
       2 ^ nat \<lfloor>j1\<rfloor>\<^sub>\<nat>) = _` [simplified, symmetric]
    `mk_ref w = mk_ref w1`
  have "\<lfloor>w\<rfloor>\<^bsub>w32\<^esub> * 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1) =
    (?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j1\<rfloor>\<^sub>\<nat> - 1)) -
     ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j1\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j1\<rfloor>\<^sub>\<nat> mod 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1))
      mod 2 ^ nat \<lfloor>j1\<rfloor>\<^sub>\<nat>"
    by simp
  also from `\<lfloor>s1\<rfloor>\<^sub>\<nat> < \<lfloor>j1\<rfloor>\<^sub>\<nat>` `(\<lfloor>j1\<rfloor>\<^sub>\<nat> \<le> \<lfloor>i\<rfloor>\<^bsub>w64\<^esub> + 1) = _` natural_to_int_lower [of s1]
  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j1\<rfloor>\<^sub>\<nat> - 1)) -
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - (\<lfloor>j1\<rfloor>\<^sub>\<nat> - 1)) mod 2 ^ nat \<lfloor>j1\<rfloor>\<^sub>\<nat> mod 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1) =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>s1\<rfloor>\<^sub>\<nat>) * 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1)"
    by (simp add: mod_mod_cancel le_imp_power_dvd
      mod_div_equality' [symmetric] zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric])
  also from `\<lfloor>s1\<rfloor>\<^sub>\<nat> < \<lfloor>j1\<rfloor>\<^sub>\<nat>`
  have "?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>s1\<rfloor>\<^sub>\<nat>) * 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1) mod 2 ^ nat \<lfloor>j1\<rfloor>\<^sub>\<nat> =
    ?e div 2 ^ nat (\<lfloor>i\<rfloor>\<^bsub>w64\<^esub> - \<lfloor>s1\<rfloor>\<^sub>\<nat>) mod 2 ^ nat (\<lfloor>s1\<rfloor>\<^sub>\<nat> + 1) * 2 ^ nat (\<lfloor>j1\<rfloor>\<^sub>\<nat> - \<lfloor>s1\<rfloor>\<^sub>\<nat> - 1)"
    by (simp add: mult_mod_left power_add [symmetric] nat_add_distrib [symmetric]
      natural_to_int_lower)
  finally show ?thesis
    using `\<lfloor>r224b\<rfloor>\<^sub>\<nat> = \<lfloor>s\<rfloor>\<^sub>\<nat> + 1` `mk_ref s = mk_ref s1`
    by simp
qed

why3_end

end
