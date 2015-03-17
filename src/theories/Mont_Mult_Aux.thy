theory Mont_Mult_Aux
imports LibSPARKcrypto
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

lemma div_power':
  assumes "n \<le> m" "x \<noteq> 0"
  shows "(x::'a::{semiring_div,ring_no_zero_divisors}) ^ m div x ^ n = x ^ (m - n)"
proof -
  from `n \<le> m` have "x ^ m div x ^ n * x ^ n = x ^ m"
    by (simp add: le_imp_power_dvd dvd_div_mult_self)
  also have "\<dots> = x ^ (m - n) * x ^ n" using `n \<le> m`
    by (simp add: power_add [symmetric])
  finally show ?thesis using `x \<noteq> 0` by simp
qed

lemmas mod_div_equality' = eq_diff_eq [THEN iffD2, OF mod_div_equality]

lemma num_of_lint_AND:
  assumes "int j < int k * i"
  and A: "\<forall>j\<in>{l..<l+i}. 0 \<le> A j \<and> A j < 2 ^ k"
  shows "(num_of_lint (2 ^ k) A l i AND 2 ^ j = 0) =
    (A (l + int (j div k)) AND 2 ^ (j mod k) = 0)"
proof -
  from zero_zle_int `int j < int k * i`
  have "0 < int k * i"
    by (rule le_less_trans)
  then have "0 < k" by (simp add: zero_less_mult_iff)
  then have "int j div int k * int k \<le> int j"
    by (simp add: mod_div_equality')
  with `int j < int k * i`
  have "int j div int k * int k < int k * i"
    by simp
  with `0 < k`
  have "0 \<le> i - int (j div k) - 1"
    by (simp add: zdiv_int)
  have "(num_of_lint (2 ^ k) A l i AND 2 ^ j = 0) =
    (num_of_lint (2 ^ k) A l
      (int (j div k) + (1 + (i - int (j div k) - 1))) div
        2 ^ (k * (j div k)) div 2 ^ (j mod k) mod 2 = 0)"
    by (simp add: AND_div_mod zdiv_zmult2_eq [symmetric]
      power_add [symmetric])
  also have "num_of_lint (2 ^ k) A l
      (int (j div k) + (1 + (i - int (j div k) - 1))) =
    num_of_lint (2 ^ k) A l (int (j div k)) +
    2 ^ (k * (j div k)) *
      (num_of_lint (2 ^ k) A (l + int (j div k)) 1 +
       (2 ^ k) * num_of_lint (2 ^ k) A (l + int (j div k) + 1)
         (i - int (j div k) - 1))"
    using `0 \<le> i - int (j div k) - 1`
    by (simp only: num_of_lint_sum) (simp add: power_mult)
  also have "(num_of_lint (2 ^ k) A l (int (j div k)) +
    2 ^ (k * (j div k)) *
      (num_of_lint (2 ^ k) A (l + int (j div k)) 1 +
       (2 ^ k) * num_of_lint (2 ^ k) A (l + int (j div k) + 1)
         (i - int (j div k) - 1))) div 2 ^ (k * (j div k)) =
    num_of_lint (2 ^ k) A l (int (j div k)) div 2 ^ (k * (j div k)) +
    A (l + int (j div k)) +
    (2 ^ k) * num_of_lint (2 ^ k) A (l + int (j div k) + 1)
      (i - int (j div k) - 1)"
    by simp
  also from A `0 \<le> i - int (j div k) - 1`
    num_of_lint_upper [of l "int (j div k)" A "2 ^ k"]
  have "num_of_lint (2 ^ k) A l (int (j div k)) div 2 ^ (k * (j div k)) = 0"
    by (simp add: div_pos_pos_trivial num_of_lint_lower power_mult)
  also have "(0 + A (l + int (j div k)) +
      2 ^ k * num_of_lint (2 ^ k) A (l + int (j div k) + 1)
        (i - int (j div k) - 1)) div 2 ^ (j mod k) =
    A (l + int (j div k)) div 2 ^ (j mod k) +
    2 ^ (k - j mod k) * num_of_lint (2 ^ k) A (l + int (j div k) + 1)
      (i - int (j div k) - 1)" (is "((0 + ?a) + ?b) div _ = _")
    using `0 < k`
    by (simp add: zdiv_zadd1_eq [of ?a ?b]
      dvd_div_mult [symmetric] le_imp_power_dvd div_power' dvd_imp_mod_0)
  also have "\<dots> mod 2 =
    (A (l + int (j div k)) div 2 ^ (j mod k) mod 2 +
     2 ^ (k - j mod k) *
     num_of_lint (2 ^ k) A (l + int (j div k) + 1)
       (i - int (j div k) - 1) mod 2) mod 2"
    by simp
  finally show ?thesis using `0 < k`
    by (simp add: dvd_imp_mod_0 AND_div_mod)
qed

lemmas num_of_lint_AND_32 = num_of_lint_AND [where k=32, simplified]

lemma mod_eq_1: "((x::int) mod 2 = 1) = (x mod 2 \<noteq> 0)"
  by simp

lemma OR_plus1: "(x::int) * 2 OR 1 = x * 2 + 1"
  by (simp add: plus_and_or [symmetric, of "x * 2" 1]
    AND_div_mod [where n=0, simplified])

lemma mod_mult_add:
  assumes "0 < (b::int)" "0 \<le> d" "d < c"
  shows "a mod b * c + d = (a * c + d) mod (b * c)"
proof -
  from `0 < b` have "a mod b < b" by (rule pos_mod_bound)
  then have "a mod b + 1 \<le> b" by simp
  with `0 \<le> d` `d < c` have "(a mod b + 1) * c \<le> b * c" by simp
  with `d < c` have "a mod b * c + d < b * c"
    by (simp add: ring_distribs)
  with `0 < b` `0 \<le> d` `d < c`
  have "a mod b * c + d = (a mod b * c + d) mod (b * c)"
    by (simp add: mod_pos_pos_trivial mult_nonneg_nonneg)
  also have "\<dots> = (a * c mod (b * c) + d) mod (b * c)"
    by (simp add: mult_ac)
  finally show ?thesis
    by (simp only: mod_add_left_eq [symmetric])
qed

end
