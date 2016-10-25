theory lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_6
imports "../Mont_Mult"
begin

why3_open "lscmnbignum_Lsc__bignum__mont_mult__subprogram_def_WP_parameter_def_6.xml"

why3_vc WP_parameter_def
proof -
  let "(?l mod _ = _) = _" = ?thesis
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
  finally show ?thesis by (simp only: diff_add_eq [symmetric] base_eq eq_True
    math_int_conv math_int_of_int_inv)
qed

why3_end

end
