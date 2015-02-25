theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_2
imports "../LibSPARKcrypto"
begin

lemma zdiv_zadd3: "((a::int) + b + c) div d =
  a div d + b div d + c div d + (a mod d + b mod d + c mod d) div d"
  by (simp add:
    zdiv_zadd1_eq [of "a + b" c]
    zdiv_zadd1_eq [of a b]
    zdiv_zadd1_eq [of "a mod d + b mod d" "c mod d"])

lemma zdiv_zadd3': "((a::int) + x * b + y * c) div d =
  a div d + x * (b div d) + y * (c div d) +
  (a mod d + x * (b mod d) + y * (c mod d)) div d"
  by (simp add:
    zdiv_zadd3 [of a "x * b" "y * c"]
    zdiv_zadd3 [of "a mod d" "x * (b mod d)" "y * (c mod d)"]
    zdiv_zmult1_eq [of x b d]
    zdiv_zmult1_eq [of y c d])

lemma add_carry:
  assumes "0 \<le> a" and "0 \<le> b" and "a < c" and "b < c"
  shows "num_of_bool ((a + b) mod c < b) = (a + b) div c"
proof (cases "a + b < c")
  case True
  with assms show ?thesis
    by (auto simp add: mod_pos_pos_trivial div_pos_pos_trivial
      split add: num_of_bool_split)
next
  case False
  with assms div_add_self2 [of c "a + b - c"]
    minus_mod_self2 [of "a + b" c, symmetric]
  show ?thesis
    by (auto simp add: not_less div_pos_pos_trivial
      mod_pos_pos_trivial simp del: minus_mod_self2
      split add: num_of_bool_split)
qed

lemma hcarry_le1:
  assumes eq: "(a::int) + b * x + c * y + lcarry + B * hcarry =
    r + B ^ n * (lcarry' + B * hcarry')"
  and "0 \<le> a" and "a < B ^ n"
  and "0 \<le> b" and "b < B ^ n" and "0 \<le> x" and "x < B"
  and "0 \<le> c" and "c < B ^ n" and "0 \<le> y" and "y < B"
  and "0 \<le> lcarry" and "lcarry < B"
  and "0 \<le> hcarry" and "hcarry \<le> 1"
  and "0 \<le> r" and "r < B ^ n"
  and "0 \<le> lcarry'" and "lcarry' < B"
  and "0 \<le> hcarry'"
  and "1 < B"
  shows "hcarry' \<le> 1"
proof -
  from `1 < B` have "0 < B ^ n" and "0 < B" by simp_all
  from `a < B ^ n` have "a \<le> B ^ n - 1" by simp
  moreover from `b < B ^ n` `x < B` `0 \<le> x` `1 < B`
  have "b * x \<le> (B ^ n - 1) * (B - 1)" (is "_ \<le> ?bb")
    by (simp add: mult_mono)
  moreover from `c < B ^ n` `y < B` `0 \<le> y` `1 < B`
  have "c * y \<le> (B ^ n - 1) * (B - 1)"
    by (simp add: mult_mono)
  moreover from `lcarry < B` have "lcarry \<le> B - 1" by simp
  moreover from `hcarry \<le> 1` `0 \<le> hcarry` `1 < B`
  have "B * hcarry \<le> B"
    by (simp add: mult_mono)
  ultimately have "a + b * x + c * y + lcarry + B * hcarry \<le>
    B ^ n - 1 + ?bb + ?bb + (B - 1) + B"
    by (simp only: add_mono)
  with eq have "r + B ^ n * (lcarry' + B * hcarry') \<le> B ^ n * (2 * B - 1)"
    by (simp add: ring_distribs mult_ac)
  from zdiv_mono1 [OF this `0 < B ^ n`] `1 < B` `0 \<le> r` `r < B ^ n`
  have "lcarry' + B * hcarry' \<le> 2 * B - 1"
    by (simp add: div_pos_pos_trivial)
  note zdiv_mono1 [OF this `0 < B`]
  also have "(2 * B - 1) div B = ((- 1) + 2 * B) div B"
    by (simp add: add.commute [of "- 1"])
  also from `1 < B` have "\<dots> = 1"
    by (simp add: zdiv_zminus1_eq_if div_pos_pos_trivial
      mod_pos_pos_trivial del: uminus_add_conv_diff)
  finally show ?thesis using `1 < B` `0 \<le> lcarry'` `lcarry' < B`
    by (simp add: div_pos_pos_trivial)
qed

lemma inv_sum_eq:
  assumes "(b::int) * b' mod m = 1"
  shows "(x * b' ^ n + y) * b' mod m = (x + b ^ n * y) * b' ^ (n + 1) mod m"
proof -
  have "(x * b' ^ n + y) * b' mod m = (x * b' * b' ^ n + y * (b' mod m)) mod m"
    by (simp add: ring_distribs mult_ac)
  also from assms have "b' mod m = b' * (b * b' mod m) ^ n mod m"
    by simp
  also have "\<dots> = b ^ n * b' ^ (n + 1) mod m"
    by (simp add: power_mult_distrib mult_ac)
  finally show ?thesis
    by (simp add: ring_distribs mult_ac)
qed

lemma mod_cong: "a = b \<Longrightarrow> a mod m = b mod m"
  by simp

lemma div_cong: "a = b \<Longrightarrow> a div m = b div m"
  by simp

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_2.xml"

why3_vc WP_parameter_def
proof -
  let "(?l mod _ = _) = _" = ?C1
  let ?R = "Base ^ nat (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>)"
  let ?R' = "Base ^ nat (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?j = "i - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>"
  let ?a = "num_of_big_int (word32_to_int \<circ> a1) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?b = "num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> ?j"
  let ?b' = "num_of_big_int' b \<lfloor>b_first\<rfloor>\<^sub>\<nat> (?j + 1)"
  let ?c = "num_of_big_int' c \<lfloor>c_first\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?m = "num_of_big_int' m \<lfloor>m_first\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1)"
  let ?bi = "\<lfloor>elts b (\<lfloor>b_first\<rfloor>\<^sub>\<nat> + ?j)\<rfloor>\<^bsub>w32\<^esub>"
  let ?u = "(\<lfloor>a1 \<lfloor>a_first1\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> + ?bi * \<lfloor>elts c \<lfloor>c_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub>) * \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> mod Base"
  let ?a' = "?a + ?bi * ?c + ?u * ?m + ?R' * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub>"
  note single_add_mult_mult =
    `(_ = \<lfloor>lsc__bignum__single_add_mult_mult__a1\<rfloor>\<^bsub>w32\<^esub> + _) = True`
    [simplified `a1 \<lfloor>a_first1\<rfloor>\<^sub>\<nat> = lsc__bignum__single_add_mult_mult__a` [symmetric]
     `\<lfloor>o2\<rfloor>\<^bsub>w32\<^esub> = _` `\<lfloor>o3\<rfloor>\<^bsub>w32\<^esub> = _` `\<lfloor>o4\<rfloor>\<^bsub>w32\<^esub> = _` emod_def,
     simplified, simplified base_eq]
  note add_mult_mult =
    `(_ = num_of_big_int' (Array a2 _) _ _ + _) = True`
    [simplified, simplified base_eq emod_def `\<lfloor>o4\<rfloor>\<^bsub>w32\<^esub> = _` fun_upd_comp, simplified]
  note word_of_boolean = `(_ = num_of_bool _) = _`
    [simplified, simplified `\<lfloor>o5\<rfloor>\<^bsub>w32\<^esub> = _`]
  note invariant =
    `((num_of_big_int' (Array a1 _) _ _ + _) mod _ = _) = True`
    [simplified base_eq, simplified]
  note m_inv = `(1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> emod Base) emod Base = 0`
    [unfolded emod_def, simplified]

  have "\<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> \<le> 1"
    by (rule hcarry_le1 [where n=1 and lcarry=0 and hcarry=0, simplified, OF single_add_mult_mult])
      (simp_all add: word32_to_int_lower word32_to_int_upper')

  then have "\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> \<le> 1"
    by (rule_tac hcarry_le1 [OF add_mult_mult])
      (simp_all add: word32_to_int_lower word32_to_int_upper'
         num_of_lint_lower num_of_lint_upper)

  have "?a' mod Base =
    ((?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base +
     ?R' * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> mod Base) mod Base"
    by simp
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "(?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base =
    ((\<lfloor>a1 \<lfloor>a_first1\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> + ?bi * \<lfloor>elts c \<lfloor>c_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub>) * ((1 + \<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub> * \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub>) mod Base)) mod Base"
    by (simp add: num_of_lint_mod word32_to_int_lower word32_to_int_upper'
      ring_distribs add_ac mult_ac del: num_of_lint_sum)
  also note m_inv
  finally have "?a' mod Base = 0"
    using `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
    by (simp add: nat_add_distrib o_def)
  moreover from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` `(1 < ?m) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^bsub>w32\<^esub>" "word32_to_int o elts m" _ 32, simplified, OF m_inv])
  ultimately have a_div: "?a' div Base mod ?m = ?a' * minv ?m Base mod ?m"
    by (simp add: inv_div)

  from `\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> \<le> 1` `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>` word_of_boolean
    `\<lfloor>o5\<rfloor>\<^bsub>w32\<^esub> = _` `\<lfloor>o6\<rfloor>\<^bsub>w32\<^esub> = _`
  have "?l = num_of_big_int (word32_to_int \<circ> a2) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    ?R * ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base) +
    Base * ?R * ((\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> + num_of_bool
      ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base < \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>)) mod Base)"
    by (simp add: nat_add_distrib emod_def base_eq fun_upd_comp)
  also from `\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> \<le> 1` num_of_bool_le1
  have "\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> +
    num_of_bool ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base < \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) \<le> 1 + 1"
    by (rule add_mono)
  with word32_to_int_lower [of carry11] word32_to_int_lower [of carry21]
    word32_to_int_lower [of a_msw]
    word32_to_int_upper [of a_msw] word32_to_int_upper [of carry11]
  have "(\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> +
      num_of_bool ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base < \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>)) mod Base =
    \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> + (\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) div Base"
    by (simp add: num_of_bool_ge0 mod_pos_pos_trivial add_carry)
  also have "num_of_big_int (word32_to_int \<circ> a2) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    ?R * ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base) +
    Base * ?R * (\<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> + (\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) div Base) =
    num_of_big_int (word32_to_int \<circ> a2) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    ?R * ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) mod Base +
      Base * \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub> + Base * ((\<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub>) div Base))"
    by (simp only: ring_distribs add_ac mult_ac)
  also have "\<dots> = num_of_big_int (word32_to_int \<circ> a2) \<lfloor>a_first1\<rfloor>\<^sub>\<nat> (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    ?R * (\<lfloor>carry11\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry21\<rfloor>\<^bsub>w32\<^esub>) + ?R * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub>"
    by (simp add: ring_distribs add_ac)
  also note add_mult_mult [symmetric]
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "num_of_big_int (word32_to_int \<circ> a1) (\<lfloor>a_first1\<rfloor>\<^sub>\<nat> + 1) (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) +
    num_of_big_int' c (\<lfloor>c_first\<rfloor>\<^sub>\<nat> + 1) (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * ?bi +
    num_of_big_int' m (\<lfloor>m_first\<rfloor>\<^sub>\<nat> + 1) (\<lfloor>a_last1\<rfloor>\<^sub>\<nat> - \<lfloor>a_first1\<rfloor>\<^sub>\<nat>) * ?u +
    \<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> + ?R * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> =
    ?a div Base + ?bi * (?c div Base) + ?u * (?m div Base) +
      (\<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub>) + ?R * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub>"
    by (simp add: num_of_lint_div word32_to_int_lower word32_to_int_upper'
      fun_upd_comp del: num_of_lint_sum)
  also from single_add_mult_mult [THEN div_cong, of Base]
    word32_to_int_lower [of lsc__bignum__single_add_mult_mult__a1]
    word32_to_int_upper' [of lsc__bignum__single_add_mult_mult__a1]
  have "\<lfloor>carry1\<rfloor>\<^bsub>w32\<^esub> + Base * \<lfloor>carry2\<rfloor>\<^bsub>w32\<^esub> =
    (\<lfloor>a1 \<lfloor>a_first1\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> + ?bi * \<lfloor>elts c \<lfloor>c_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> + \<lfloor>elts m \<lfloor>m_first\<rfloor>\<^sub>\<nat>\<rfloor>\<^bsub>w32\<^esub> * ?u) div Base"
    by (simp only: div_mult_self2 div_pos_pos_trivial)
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "\<dots> = (?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) div Base"
    by (simp add: num_of_lint_mod mult.commute word32_to_int_lower word32_to_int_upper'
      del: num_of_lint_sum)
  also note zdiv_zadd3' [symmetric]
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> < \<lfloor>a_last1\<rfloor>\<^sub>\<nat>`
  have "(?a + ?bi * ?c + ?u * ?m) div Base + ?R * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub> = ?a' div Base"
    by (simp add: nat_add_distrib mult.assoc)
  finally have "?l = ?a' div Base" .
  then have "?l mod ?m = ?a' div Base mod ?m" by (rule mod_cong)
  also note a_div
  also have "(?a' * minv ?m Base) mod ?m =
    (((?a + ?R' * \<lfloor>a_msw\<rfloor>\<^bsub>w32\<^esub>) mod ?m +
      ?bi * ?c) * minv ?m Base) mod ?m"
    by (simp add: add_ac)
  also note invariant
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
  have "(?b * ?c * minv ?m Base ^ nat ?j mod ?m +
     ?bi * ?c) * minv ?m Base mod ?m =
    (?b * ?c + Base ^ nat ?j * ?bi * ?c) *
    minv ?m Base ^ nat (?j + 1) mod ?m"
    by (simp add: nat_add_distrib inv_sum_eq [OF Base_inv]) (simp add: mult_ac)
  also from `\<lfloor>a_first1\<rfloor>\<^sub>\<nat> \<le> i`
  have "?b * ?c + Base ^ nat ?j * ?bi * ?c =
    ?b' * ?c"
    by (simp add: nat_add_distrib ring_distribs)
  finally show ?C1 by (simp only: diff_add_eq [symmetric] base_eq eq_True)

  have "0 \<le> ?c" by (simp_all add: num_of_lint_lower word32_to_int_lower)
  with `(?c < ?m) = _`
  have "?bi * ?c \<le> (Base - 1) * (?m - 1)"
    by - (rule mult_mono, simp_all add: word32_to_int_upper')
  moreover  have "0 \<le> ?m"
    by (simp_all add: num_of_lint_lower word32_to_int_lower)
  then have "?u * ?m \<le> (Base - 1) * ?m"
    by (simp_all add: mult_right_mono)
  ultimately have "?a' \<le> 2 * Base * ?m - Base - 1"
    using `(num_of_big_int' (Array a1 _) _ _ + _ < _) = _`
    by (simp add: base_eq)
  then have "?a' div Base \<le> (2 * Base * ?m - Base - 1) div Base"
    by simp
  also have "\<dots> < 2 * ?m - 1" by simp
  also note `?l = ?a' div Base` [symmetric]
  finally show ?C2 by (simp only: eq_True)
qed

why3_end

end
