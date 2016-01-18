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
  assumes "0 \<le> (a::int)" and "0 \<le> b" and "a < c" and "b < c"
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
  let ?R = "Base ^ nat (a_last - a_first)"
  let ?R' = "Base ^ nat (a_last - a_first + 1)"
  let ?j = "i1 - a_first"
  let ?a = "num_of_big_int (word32_to_int \<circ> a1) a_first (a_last - a_first + 1)"
  let ?b = "num_of_big_int (word32_to_int \<circ> elts b) b_first ?j"
  let ?b' = "num_of_big_int (word32_to_int \<circ> elts b) b_first (?j + 1)"
  let ?c = "num_of_big_int (word32_to_int \<circ> elts c) c_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int (word32_to_int \<circ> elts m) m_first (a_last - a_first + 1)"
  let ?bi = "\<lfloor>elts b (b_first + ?j)\<rfloor>\<^sub>s"
  let ?u = "(\<lfloor>a1 a_first\<rfloor>\<^sub>s + ?bi * \<lfloor>elts c c_first\<rfloor>\<^sub>s) * \<lfloor>m_inv\<rfloor>\<^sub>s mod Base"
  let ?a' = "?a + ?bi * ?c + ?u * ?m + ?R' * \<lfloor>a_msw1\<rfloor>\<^sub>s"
  note single_add_mult_mult =
    `(_ = math_int_from_word o1 + _) = True`
    [simplified,
     simplified uint_word_ariths, simplified,
     simplified base_eq int_of_math_int_Base]
  note add_mult_mult =
    `(_ = num_of_big_int' (Array a2 _) _ _ + _) = True`
    [simplified, simplified base_eq fun_upd_comp uint_word_ariths, simplified]
  note word_of_boolean = `(_ = num_of_bool _) = _`
    [simplified `o2 = _` BV32.ult_def, simplified,
     simplified uint_word_ariths, simplified]
  note invariant =
    `((num_of_big_int' (Array a1 _) _ _ + _) mod _ = _) = True`
    [simplified base_eq, simplified]
  note m_inv = `of_int 1 + m_inv * elts m m_first = of_int 0`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  have "uint carry2 \<le> 1"
    by (rule hcarry_le1 [where n=1 and lcarry=0 and hcarry=0, simplified, OF single_add_mult_mult])
      (simp_all add: uint_lt [where 'a=32, simplified])

  then have "uint carry21 \<le> 1"
    by (rule_tac hcarry_le1 [OF add_mult_mult])
      (simp_all add: uint_lt [where 'a=32, simplified] word32_to_int_lower word32_to_int_upper'
         num_of_lint_lower num_of_lint_upper)

  have "?a' mod Base =
    ((?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base +
     ?R' * \<lfloor>a_msw1\<rfloor>\<^sub>s mod Base) mod Base"
    by simp
  also from `a_first < a_last`
  have "(?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base =
    ((\<lfloor>a1 a_first\<rfloor>\<^sub>s + ?bi * \<lfloor>elts c c_first\<rfloor>\<^sub>s) * ((1 + \<lfloor>m_inv\<rfloor>\<^sub>s * \<lfloor>elts m m_first\<rfloor>\<^sub>s) mod Base)) mod Base"
    by (simp add: num_of_lint_mod word32_to_int_lower word32_to_int_upper'
      ring_distribs add_ac mult_ac del: num_of_lint_sum)
  also note m_inv
  finally have "?a' mod Base = 0"
    using `a_first < a_last`
    by (simp add: nat_add_distrib o_def)
  moreover from `a_first < a_last` `(math_int_from_word (of_int 1) < num_of_big_int' m _ _) = _`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp add: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv]
      del: num_of_lint_sum)
  ultimately have a_div: "?a' div Base mod ?m = ?a' * minv ?m Base mod ?m"
    by (simp add: inv_div)

  from `uint carry21 \<le> 1` `a_first < a_last` word_of_boolean
    `o2 = _`
  have "int_of_math_int ?l = num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first) +
    ?R * ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base) +
    Base * ?R * ((\<lfloor>carry21\<rfloor>\<^sub>s + num_of_bool
      ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base < \<lfloor>carry11\<rfloor>\<^sub>s)) mod Base)"
    by (simp add: nat_add_distrib base_eq fun_upd_comp uint_word_ariths
      word32_to_int_def BV32.ult_def)
  also from `uint carry21 \<le> 1` [folded word32_to_int_def] num_of_bool_le1
  have "\<lfloor>carry21\<rfloor>\<^sub>s +
    num_of_bool ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base < \<lfloor>carry11\<rfloor>\<^sub>s) \<le> 1 + 1"
    by (rule add_mono)
  with word32_to_int_lower [of carry11] word32_to_int_lower [of carry21]
    word32_to_int_lower [of a_msw1]
    word32_to_int_upper [of a_msw1] word32_to_int_upper [of carry11]
  have "(\<lfloor>carry21\<rfloor>\<^sub>s +
      num_of_bool ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base < \<lfloor>carry11\<rfloor>\<^sub>s)) mod Base =
    \<lfloor>carry21\<rfloor>\<^sub>s + (\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) div Base"
    by (simp add: num_of_bool_ge0 mod_pos_pos_trivial add_carry)
  also have "num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first) +
    ?R * ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base) +
    Base * ?R * (\<lfloor>carry21\<rfloor>\<^sub>s + (\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) div Base) =
    num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first) +
    ?R * ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) mod Base +
      Base * \<lfloor>carry21\<rfloor>\<^sub>s + Base * ((\<lfloor>a_msw1\<rfloor>\<^sub>s + \<lfloor>carry11\<rfloor>\<^sub>s) div Base))"
    by (simp only: ring_distribs add_ac mult_ac)
  also have "\<dots> = num_of_big_int (word32_to_int \<circ> a2) a_first (a_last - a_first) +
    ?R * (\<lfloor>carry11\<rfloor>\<^sub>s + Base * \<lfloor>carry21\<rfloor>\<^sub>s) + ?R * \<lfloor>a_msw1\<rfloor>\<^sub>s"
    by (simp add: ring_distribs add_ac)
  also note add_mult_mult [symmetric, folded word32_to_int_def]
  also from `a_first < a_last`
  have "num_of_big_int (word32_to_int \<circ> a1) (a_first + 1) (a_last - a_first) +
    num_of_big_int (word32_to_int \<circ> elts c) (c_first + 1) (a_last - a_first) * ?bi +
    num_of_big_int (word32_to_int \<circ> elts m) (m_first + 1) (a_last - a_first) * ?u +
    \<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s + ?R * \<lfloor>a_msw1\<rfloor>\<^sub>s =
    ?a div Base + ?bi * (?c div Base) + ?u * (?m div Base) +
      (\<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s) + ?R * \<lfloor>a_msw1\<rfloor>\<^sub>s"
    by (simp add: num_of_lint_div word32_to_int_lower word32_to_int_upper'
      fun_upd_comp del: num_of_lint_sum)
  also from single_add_mult_mult [THEN div_cong, of Base]
    word32_to_int_lower [of o1]
    word32_to_int_upper' [of o1]
  have "\<lfloor>carry1\<rfloor>\<^sub>s + Base * \<lfloor>carry2\<rfloor>\<^sub>s =
    (\<lfloor>a1 a_first\<rfloor>\<^sub>s + ?bi * \<lfloor>elts c c_first\<rfloor>\<^sub>s + \<lfloor>elts m m_first\<rfloor>\<^sub>s * ?u) div Base"
    by (simp only: div_mult_self2 div_pos_pos_trivial word32_to_int_def)
  also from `a_first < a_last`
  have "\<dots> = (?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) div Base"
    by (simp add: num_of_lint_mod mult.commute word32_to_int_lower word32_to_int_upper'
      del: num_of_lint_sum)
  also note zdiv_zadd3' [symmetric]
  also from `a_first < a_last`
  have "(?a + ?bi * ?c + ?u * ?m) div Base + ?R * \<lfloor>a_msw1\<rfloor>\<^sub>s = ?a' div Base"
    by (simp add: nat_add_distrib mult.assoc)
  finally have "int_of_math_int ?l = ?a' div Base" .
  then have "int_of_math_int ?l mod ?m = ?a' div Base mod ?m" by (rule mod_cong)
  also note a_div
  also have "(?a' * minv ?m Base) mod ?m =
    (((?a + ?R' * \<lfloor>a_msw1\<rfloor>\<^sub>s) mod ?m +
      ?bi * ?c) * minv ?m Base) mod ?m"
    by (simp add: add_ac)
  also note invariant [folded word32_to_int_def]
  also from `a_first \<le> i1`
  have "(?b * ?c * minv ?m Base ^ nat ?j mod ?m +
     ?bi * ?c) * minv ?m Base mod ?m =
    (?b * ?c + Base ^ nat ?j * ?bi * ?c) *
    minv ?m Base ^ nat (?j + 1) mod ?m"
    by (simp add: nat_add_distrib inv_sum_eq [OF Base_inv]) (simp add: mult_ac)
  also from `a_first \<le> i1`
  have "?b * ?c + Base ^ nat ?j * ?bi * ?c =
    ?b' * ?c"
    by (simp add: nat_add_distrib ring_distribs)
  finally show ?C1 by (simp only: diff_add_eq [symmetric] base_eq eq_True
    math_int_conv math_int_of_int_inv)

  have "0 \<le> ?c" by (simp_all add: num_of_lint_lower word32_to_int_lower)
  with `(num_of_big_int' c _ _ < num_of_big_int' m _ _) = _`
  have "?bi * ?c \<le> (Base - 1) * (?m - 1)"
    by - (rule mult_mono, simp_all add: word32_to_int_upper')
  moreover  have "0 \<le> ?m"
    by (simp_all add: num_of_lint_lower word32_to_int_lower)
  then have "?u * ?m \<le> (Base - 1) * ?m"
    by (simp_all add: mult_right_mono)
  ultimately have "?a' \<le> 2 * Base * ?m - Base - 1"
    using `(num_of_big_int' (Array a1 _) _ _ + _ < _) = _`
    by (simp add: base_eq word32_to_int_def)
  then have "?a' div Base \<le> (2 * Base * ?m - Base - 1) div Base"
    by simp
  also have "\<dots> < 2 * ?m - 1" by simp
  also note `int_of_math_int ?l = ?a' div Base` [symmetric]
  finally show ?C2 by (simp add: o_def)
qed

why3_end

end
