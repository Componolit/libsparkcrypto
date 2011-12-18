theory Mont_Mult
imports Bignum
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
    zmod_zsub_self [of "a + b" c, symmetric]
  show ?thesis
    by (auto simp add: not_less div_pos_pos_trivial
      mod_pos_pos_trivial simp del: zmod_zsub_self
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
    by (simp add: add_commute [of "- 1"] del: arith_simps)
  also from `1 < B` have "\<dots> = 1"
    by (simp add: zdiv_zminus1_eq_if div_pos_pos_trivial
      mod_pos_pos_trivial del: arith_simps) simp
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

spark_open "$VCG_DIR/lsc_/bignum/mont_mult.siv"

spark_vc procedure_mont_mult_5
  using `\<forall>k. a_first \<le> k \<and> k \<le> a_last \<longrightarrow> a__1 k = 0`
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
  by (simp_all add: num_of_lint_all0)

spark_vc procedure_mont_mult_9
  using `bounds _ _ _ _ b`
    `b__index__subtype__1__first \<le> b_first`
    `b_first + (a_last - a_first) \<le> b__index__subtype__1__last`
    `a_first \<le> loop__1__i` `loop__1__i \<le> a_last`
    `b__index__subtype__1__last \<le> 2147483647`
  by simp_all

spark_vc procedure_mont_mult_13
  using `m_first + (a_last - a_first) \<le> m__index__subtype__1__last`
    `m__index__subtype__1__last \<le> 2147483647`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
    `c__index__subtype__1__last \<le> 2147483647`
    `a_first < a_last`
  by simp_all

spark_vc procedure_mont_mult_18
proof -
  let "?l mod _ = _" = ?C1
  let ?R = "Base ^ nat (a_last - a_first)"
  let ?R' = "Base ^ nat (a_last - a_first + 1)"
  let ?j = "loop__1__i - a_first"
  let ?a = "num_of_big_int a a_first (a_last - a_first + 1)"
  let ?b = "num_of_big_int b b_first ?j"
  let ?b' = "num_of_big_int b b_first (?j + 1)"
  let ?c = "num_of_big_int c c_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int m m_first (a_last - a_first + 1)"
  let ?bi = "b (b_first + ?j)"
  let ?u = "(a a_first + ?bi * c c_first) * m_inv mod Base"
  let ?a' = "?a + ?bi * ?c + ?u * ?m + ?R' * a_msw"
  note single_add_mult_mult = `_ = a__2 a_first + _`
  note add_mult_mult = `_ = num_of_big_int a__3 _ _ + _` [simplified]
  note word_of_boolean = `word_of_boolean _ = _`
  note invariant = `(?a + _) mod _ = _`
  note a_in_range = `bounds _ _ _ _ a`
  note b_in_range = `bounds _ _ _ _ b`
  note c_in_range = `bounds _ _ _ _ c`
  note m_in_range = `bounds _ _ _ _ m`
  note a2_in_range = `bounds _ _ _ _ a__2`
  note a3_in_range = `bounds _ _ _ _ a__3`
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from b_in_range
    `b__index__subtype__1__first \<le> b_first + ?j`
    `b_first + ?j \<le> b__index__subtype__1__last`
  have bi_bounds: "0 \<le> ?bi" "?bi < Base"
    by simp_all
  from a_in_range
    `a__index__subtype__1__first \<le> a_first`
    `a_first \<le> a__index__subtype__1__last`
  have a: "0 \<le> a a_first" "a a_first < Base" by simp_all
  moreover note bi_bounds
  moreover from c_in_range
    `a_first < a_last` `c__index__subtype__1__first \<le> c_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
  have c: "0 \<le> c c_first" "c c_first < Base" by simp_all
  moreover from m_in_range
    `a_first < a_last` `m__index__subtype__1__first \<le> m_first`
    `m_first + (a_last - a_first) \<le> m__index__subtype__1__last`
  have m: "0 \<le> m m_first" "m m_first < Base" by simp_all
  moreover from a2_in_range
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last` `a_first < a_last`
  have "0 \<le> a__2 a_first" and "a__2 a_first < Base" by simp_all
  moreover note `0 \<le> carry1__2` `carry1__2 \<le> _` [simplified]
    `0 \<le> carry2__2`
  ultimately have "carry2__2 \<le> 1"
    by (rule hcarry_le1 [where n=1 and lcarry=0 and hcarry=0, simplified,
      OF single_add_mult_mult, simplified]) 

  from a2_in_range
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__2 (a_first + 1) (a_last - a_first)"
    and "num_of_big_int a__2 (a_first + 1) (a_last - a_first) < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)
  moreover from c_in_range
    `c__index__subtype__1__first \<le> c_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
  have "0 \<le> num_of_big_int c (c_first + 1) (a_last - a_first)"
    and "num_of_big_int c (c_first + 1) (a_last - a_first) < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)
  moreover note bi_bounds
  moreover from m_in_range
    `m__index__subtype__1__first \<le> m_first`
    `m_first + (a_last - a_first) \<le> m__index__subtype__1__last`
  have "0 \<le> num_of_big_int m (m_first + 1) (a_last - a_first)"
    and "num_of_big_int m (m_first + 1) (a_last - a_first) < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)
  moreover note `0 \<le> carry1__2` `carry1__2 \<le> _` [simplified]
    `0 \<le> carry2__2` `carry2__2 \<le> 1`
  moreover from a3_in_range
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have "0 \<le> num_of_big_int a__3 a_first (a_last - a_first)"
    and "num_of_big_int a__3 a_first (a_last - a_first) < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)
  moreover note `0 \<le> carry1__3` `carry1__3 \<le> _` [simplified]
    `0 \<le> carry2__3`
  ultimately have "carry2__3 \<le> 1"
    by (rule hcarry_le1 [OF add_mult_mult, simplified])

  have "?a' mod Base =
    ((?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base +
     ?R' * a_msw mod Base) mod Base"
    by simp
  also from `a_first < a_last` a c m
  have "(?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) mod Base =
    ((a a_first + ?bi * c c_first) * ((1 + m_inv * m m_first) mod Base)) mod Base"
    by (simp only: num_of_lint_mod)
      (simp add: ring_distribs add_ac mult_ac)
  also note m_inv
  finally have "?a' mod Base = 0"
    using `a_first < a_last`
    by (simp add: nat_add_distrib)
  moreover from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])
  ultimately have a_div: "?a' div Base mod ?m = ?a' * minv ?m Base mod ?m"
    by (simp add: inv_div)

  from `carry2__3 \<le> 1` `a_first < a_last` word_of_boolean
  have "?l = num_of_big_int a__3 a_first (a_last - a_first) +
    ?R * ((a_msw + carry1__3) mod Base) +
    Base * ?R * ((carry2__3 + num_of_bool
      ((a_msw + carry1__3) mod Base < carry1__3)) mod Base)"
    by (simp add: nat_add_distrib)
  also from `carry2__3 \<le> 1` num_of_bool_le1
  have "carry2__3 +
    num_of_bool ((a_msw + carry1__3) mod Base < carry1__3) \<le> 1 + 1"
    by (rule add_mono)
  with `0 \<le> carry2__3` `0 \<le> a_msw` `0 \<le> carry1__3`
    `a_msw \<le> _` `carry1__3 \<le> _`
  have "(carry2__3 +
      num_of_bool ((a_msw + carry1__3) mod Base < carry1__3)) mod Base =
    carry2__3 + (a_msw + carry1__3) div Base"
    by (simp add: num_of_bool_ge0 mod_pos_pos_trivial add_carry)
  also have "num_of_big_int a__3 a_first (a_last - a_first) +
    ?R * ((a_msw + carry1__3) mod Base) +
    Base * ?R * (carry2__3 + (a_msw + carry1__3) div Base) =
    num_of_big_int a__3 a_first (a_last - a_first) +
    ?R * ((a_msw + carry1__3) mod Base +
      Base * carry2__3 + Base * ((a_msw + carry1__3) div Base))"
    by (simp only: ring_distribs add_ac mult_ac)
  also have "\<dots> = num_of_big_int a__3 a_first (a_last - a_first) +
    ?R * (carry1__3 + Base * carry2__3) + ?R * a_msw"
    by (simp add: ring_distribs add_ac)
  also note add_mult_mult [symmetric]
  also from `a_first < a_last` a c m
  have "num_of_big_int a__2 (a_first + 1) (a_last - a_first) +
    num_of_big_int c (c_first + 1) (a_last - a_first) * ?bi +
    num_of_big_int m (m_first + 1) (a_last - a_first) * ?u +
    carry1__2 + Base * carry2__2 + ?R * a_msw =
    ?a div Base + ?bi * (?c div Base) + ?u * (?m div Base) +
      (carry1__2 + Base * carry2__2) + ?R * a_msw"
    by (simp only: num_of_lint_div)
      (subst `a__2 = a(a_first := a__2 a_first)`, simp)
  also from single_add_mult_mult [THEN div_cong, of Base]
    `0 \<le> a__2 a_first` `a__2 a_first < Base`
  have "carry1__2 + Base * carry2__2 =
    (a a_first + ?bi * c c_first + m m_first * ?u) div Base"
    by (simp only: div_mult_self2 div_pos_pos_trivial) simp
  also from `a_first < a_last` a c m
  have "\<dots> = (?a mod Base + ?bi * (?c mod Base) + ?u * (?m mod Base)) div Base"
    by (simp only: num_of_lint_mod mult_commute)
  also note zdiv_zadd3' [symmetric]
  also from `a_first < a_last`
  have "(?a + ?bi * ?c + ?u * ?m) div Base + ?R * a_msw = ?a' div Base"
    by (simp add: nat_add_distrib mult_assoc)
  finally have "?l = ?a' div Base" .
  then have "?l mod ?m = ?a' div Base mod ?m" by (rule mod_cong)
  also note a_div
  also have "(?a' * minv ?m Base) mod ?m =
    (((?a + ?R' * a_msw) mod ?m +
      ?bi * ?c) * minv ?m Base) mod ?m"
    by (simp add: add_ac)
  also note invariant
  also from `a_first \<le> loop__1__i`
  have "(?b * ?c * minv ?m Base ^ nat ?j mod ?m +
     ?bi * ?c) * minv ?m Base mod ?m =
    (?b * ?c + Base ^ nat ?j * ?bi * ?c) *
    minv ?m Base ^ nat (?j + 1) mod ?m"
    by (simp add: nat_add_distrib inv_sum_eq [OF Base_inv]) (simp add: mult_ac)
  also from `a_first \<le> loop__1__i`
  have "?b * ?c + Base ^ nat ?j * ?bi * ?c =
    ?b' * ?c"
    by (simp add: nat_add_distrib ring_distribs)
  finally show ?C1 by (simp only: diff_add_eq [symmetric])

  from c_in_range
    `c__index__subtype__1__first \<le> c_first`
    `c_first + (a_last - a_first) \<le> c__index__subtype__1__last`
  have "0 \<le> ?c" by (simp_all add: num_of_lint_lower)
  with `?bi < Base` `?c < ?m`
  have "?bi * ?c \<le> (Base - 1) * (?m - 1)"
    by - (rule mult_mono, simp_all)
  moreover from m_in_range
    `m__index__subtype__1__first \<le> m_first`
    `m_first + (a_last - a_first) \<le> m__index__subtype__1__last`
  have "0 \<le> ?m" by (simp_all add: num_of_lint_lower)
  then have "?u * ?m \<le> (Base - 1) * ?m"
    by (simp_all add: mult_right_mono)
  ultimately have "?a' \<le> 2 * Base * ?m - Base - 1"
    using `?a + ?R' * a_msw < 2 * ?m - 1`
    by simp
  then have "?a' div Base \<le> (2 * Base * ?m - Base - 1) div Base"
    by simp
  also have "\<dots> < 2 * ?m - 1" by simp
  also note `?l = ?a' div Base` [symmetric]
  finally show ?C2 .
qed

spark_vc procedure_mont_mult_25
proof -
  let ?a = "num_of_big_int a a_first (a_last - a_first + 1)"
  let ?a_4 = "num_of_big_int a__4 a_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int m m_first (a_last - a_first + 1)"
  let ?R = "Base ^ nat (a_last - a_first + 1)"
  note sub = `?a - ?m = _`
  note invariant1 = `(?a + _) mod ?m = _`
  note invariant2 = `?a + _ < _`

  from `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have a_bounds: "0 \<le> ?a"
    by (simp_all add: num_of_lint_lower)
  from `bounds _ _ _ _ a__4`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have a4_bounds: "0 \<le> ?a_4" "?a_4 < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)
  from `bounds _ _ _ _ m`
    `m__index__subtype__1__first \<le> m_first`
    `m_first + (a_last - a_first) \<le> m__index__subtype__1__last`
  have m_bounds: "0 \<le> ?m" "?m < ?R"
    by (simp_all add: num_of_lint_lower num_of_lint_upper)

  show ?thesis
  proof (cases "a_msw = 0")
    case True
    with `a_msw \<noteq> 0 \<or> \<not> less a a_first a_last m m_first`
      `\<not> a_msw \<noteq> 0 \<longrightarrow> less _ _ _ _ _ = _`
    have "?m \<le> ?a" by simp
    moreover from True invariant2 have "?a - ?m < ?m" by simp
    ultimately have "?a_4 = (?a - ?m) mod ?m"
      using sub [THEN mod_cong, of ?R] a4_bounds m_bounds
      by (simp add: mod_pos_pos_trivial)
    with True invariant1 show ?thesis
      by (simp add: diff_add_eq)
  next
    case False
    from sub [THEN mod_cong, of ?R] a4_bounds
    have "?a_4 = (?a + ?R * a_msw - ?m) mod ?R"
      by (simp add: mod_pos_pos_trivial)
    also from False `0 \<le> a_msw` have "1 \<le> a_msw" by simp
    then have "?R * 1 \<le> ?R * a_msw" by (rule mult_left_mono) simp
    with invariant2 a_bounds m_bounds
    have "(?a + ?R * a_msw - ?m) mod ?R = (?a + ?R * a_msw - ?m) mod ?m"
      by (simp add: mod_pos_pos_trivial del: zmod_zsub_self)
    finally show ?thesis using invariant1
      by (simp add: diff_add_eq)
  qed
qed

spark_vc procedure_mont_mult_26
proof -
  let ?a = "num_of_big_int a a_first (a_last - a_first + 1)"
  let ?m = "num_of_big_int m m_first (a_last - a_first + 1)"

  from `bounds _ _ _ _ a`
    `a__index__subtype__1__first \<le> a_first`
    `a_last \<le> a__index__subtype__1__last`
  have a_bounds: "0 \<le> ?a"
    by (simp_all add: num_of_lint_lower)
  with `?a mod ?m = _` `?a < ?m`
  show ?thesis by (simp add: mod_pos_pos_trivial diff_add_eq)
qed

spark_end

end
