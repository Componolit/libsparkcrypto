theory Mont_Mult
imports LibSPARKcrypto
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

end
