theory lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_8
imports "../LibSPARKcrypto"
begin

lemma mont_mult_eq:
  assumes "B * B_inv mod m = (1::int)"
  shows "(x * B ^ n) * (y * B ^ n) * B_inv ^ n mod m = x * y * B ^ n mod m"
proof -
  have "(x * B ^ n) * (y * B ^ n) * B_inv ^ n mod m =
    x * y * B ^ n * (B * B_inv mod m) ^ n mod m"
    by (simp add: power_mult_distrib mult_ac)
  with `B * B_inv mod m = 1` show ?thesis by simp
qed

why3_open "lscmnbignum_Lsc__bignum__mont_exp__subprogram_def_WP_parameter_def_8.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> ?L"
  let ?x = "num_of_big_int' x \<lfloor>x_first\<rfloor>\<^sub>\<nat> ?L"
  let ?e = "num_of_big_int' e (i + 1) (\<lfloor>e_last\<rfloor>\<^sub>\<nat> - i)"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])

  from
    `(num_of_big_int' (Array aux33 _) _ _ = _) = _`
    `(num_of_big_int' (Array a _) _ _ = _) = _`
    `(num_of_big_int' (Array aux32 _) _ _ = _) = _`
    `(num_of_big_int' (Array aux2 _) \<lfloor>aux2_first1\<rfloor>\<^sub>\<nat> ?L = _) = _`
  have "num_of_big_int (word32_to_int o aux33) \<lfloor>aux3_first1\<rfloor>\<^sub>\<nat> ?L =
    ?x ^ nat ((?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat (j + 1)) * 2) *
    ?x * ?R mod ?m"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult.commute] base_eq)
      (simp add: mont_mult_eq [OF Base_inv] power_mult power2_eq_square)
  also have "\<dots> =
    ?x ^ nat ((?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat (j + 1)) * 2 + 1) *
    ?R mod ?m"
    by (simp add: nat_add_distrib num_of_lint_lower word32_to_int_lower
      pos_imp_zdiv_nonneg_iff mult.commute)
  also from `0 \<le> j` `j \<le> 31`
  have "(?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat (j + 1)) * 2 + 1 =
    ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat j div 2 * 2 + 1"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult.commute [of _ 2]])
  also from `_ = (if (if \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> AND 2 ^ nat j = 0 then _ else _) \<noteq> _ then _ else _)`
  have "\<dots> = ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat j div 2 * 2 +
    \<lfloor>elts e i\<rfloor>\<^bsub>w32\<^esub> div 2 ^ nat j mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    by (simp add: add.commute base_eq o_def)
qed

why3_end

end
