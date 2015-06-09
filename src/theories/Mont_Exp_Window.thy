theory Mont_Exp_Window
imports Bignum
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
  shows "(x::'a::{semiring_div,ring_1_no_zero_divisors}) ^ m div x ^ n = x ^ (m - n)"
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

spark_open "$VCG_DIR/lsc_/bignum/mont_exp_window" (lsc__bignum)

spark_vc procedure_mont_exp_window_4
  using
    `a_first < a_last`
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
    `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
       aux1__1 k = 0`
  by (simp add: num_of_lint_all0 sign_simps)

spark_vc procedure_mont_exp_window_5
proof -
  have "(2::int) ^ 0 \<le> 2 ^ nat k" by (simp add: power_increasing)
  with `a_first < a_last`
  have "2 ^ 0 * (a_last - a_first + 1) \<le> 2 ^ nat k * (a_last - a_first + 1)"
    by (simp add: mult_right_mono)
  with
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     aux4__index__subtype__1__last`
    `aux4__index__subtype__1__last \<le> 2147483647`
  show ?C1 and ?C2
    by (simp_all add: sign_simps)
  from
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
    `num_of_big_int r r_first (a_last - a_first + 1) =
     Base ^ nat (2 * (a_last - a_first + 1)) mod
     num_of_big_int m m_first (a_last - a_first + 1)`
  show ?C3 by (simp add: sign_simps)
qed

spark_vc procedure_mont_exp_window_6
  using
    `num_of_big_int aux4__3 _ _ = _`
    `1 < num_of_big_int m m_first (a_last - a_first + 1)`
  by (simp add: sign_simps)

spark_vc procedure_mont_exp_window_7
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  let ?r = "num_of_big_int r r_first ?L"
  let ?R = "Base ^ nat ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `\<forall>k. aux1_first \<le> k \<and> k \<le> aux1_first + (a_last - a_first) \<longrightarrow>
    aux1__1 k = 0`
    `a_first < a_last`
  show one: ?C1 by (simp add: num_of_lint_all0)

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from `?r = _`
  have "?r * minv ?m Base ^ nat ?L mod ?m =
    (?R * (Base * minv ?m Base mod ?m) ^ nat ?L) mod ?m"
    by (simp only: nat_mult_distrib power_mult power_mult_distrib
        power2_eq_square [simplified transfer_nat_int_numerals])
      (simp add: power_mult_distrib mult.assoc)
  then have R: "?r * minv ?m Base ^ nat ?L mod ?m = ?R mod ?m"
    by (simp add: Base_inv)

  from `num_of_big_int aux4__3 _ _ = _`
  have "num_of_big_int aux4__3 aux4_first ?L =
    ?x * (?r * minv ?m Base ^ nat ?L mod ?m) mod ?m"
    by (simp add: mult.assoc)
  with R have X: "num_of_big_int aux4__3 aux4_first ?L = ?x * ?R mod ?m"
    by simp
  with `num_of_big_int aux2__4 _ _ = _`
  show ?C2 by (simp add: mont_mult_eq [OF Base_inv])

  from `num_of_big_int aux3__2 _ _ = _` one R
  show ?C3 by simp

  from X show ?C4 by simp
qed

spark_vc procedure_mont_exp_window_10
  using `num_of_big_int aux4 _ _ = _`
  by auto

spark_vc procedure_mont_exp_window_11
proof -
  from `k \<le> 30`
  have "nat k \<le> 30" by simp
  then have "(2::int) ^ nat k \<le> 2 ^ 30"
    by (rule power_increasing) simp
  with `loop__1__h < 2 ^ nat k - 1`
  show ?thesis by simp
qed

spark_vc procedure_mont_exp_window_12
proof -
  from `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "(loop__1__h - 1) * (a_last - a_first + 1) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by simp
  with `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     aux4__index__subtype__1__last`
  show ?C3 by simp
  with `aux4__index__subtype__1__last \<le> 2147483647`
  show ?C1 by simp
  with `0 \<le> aux4_first` show ?C6 by simp
  from `1 \<le> loop__1__h` `a_first < a_last`
  have "0 \<le> (loop__1__h - 1) * (a_last - a_first + 1)"
    by (simp add: mult_nonneg_nonneg)
  with `aux4__index__subtype__1__first \<le> aux4_first`
  show ?C2 by simp
  with `a_first < a_last` show ?C4 by simp
  from `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "(loop__1__h - 1) * (a_last - a_first + 1) \<le>
    (2 ^ nat k - 2) * (a_last - a_first + 1)"
    by simp
  with `a_first < a_last`
  have "(loop__1__h - 1) * (a_last - a_first + 1) + (a_last - a_first) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by (simp add: sign_simps)
  with `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     aux4__index__subtype__1__last`
  show ?C5 by simp
qed

spark_vc procedure_mont_exp_window_13
proof -
  from `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "loop__1__h * (a_last - a_first + 1) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by simp
  with `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     aux4__index__subtype__1__last`
  show ?C3 by simp
  with `aux4__index__subtype__1__last \<le> 2147483647`
  show ?C1 by simp
  from `1 \<le> loop__1__h` `a_first < a_last`
  have "0 \<le> loop__1__h * (a_last - a_first + 1)"
    by (simp add: mult_nonneg_nonneg)
  with `aux4__index__subtype__1__first \<le> aux4_first`
  show ?C2 by simp
  from `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
  have "loop__1__h * (a_last - a_first + 1) \<le>
    (2 ^ nat k - 1) * (a_last - a_first + 1)"
    by simp
  with `a_first < a_last`
  have "loop__1__h * (a_last - a_first + 1) + (a_last - a_first) \<le>
    2 ^ nat k * (a_last - a_first + 1) - 1"
    by (simp add: sign_simps)
  with `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
     aux4__index__subtype__1__last`
  show ?C4 by simp
  with `0 \<le> aux4_first` `a_first < a_last`
    `aux4__index__subtype__1__last \<le> 2147483647`
  show ?C5 by simp
qed

spark_vc procedure_mont_exp_window_14
proof (intro strip)
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?x = "num_of_big_int x x_first ?L"
  let ?r = "num_of_big_int r r_first ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  note copy =
    `\<forall>i. aux4__index__subtype__1__first \<le> i \<and> i \<le> aux4__index__subtype__1__last \<longrightarrow>
       (aux4_first + loop__1__h * ?L \<le> i \<and>
        i \<le> aux4_first + loop__1__h * ?L + a_last - a_first \<longrightarrow>
        aux4__6 i =
        a__5 (a_first + i - (aux4_first + loop__1__h * ?L))) \<and>
       (i < aux4_first + loop__1__h * ?L \<or>
        aux4_first + loop__1__h * ?L + a_last - a_first < i \<longrightarrow>
        aux4__6 i = aux4 i)`

  fix n
  assume n: "0 \<le> n \<and> n \<le> loop__1__h"

  show "num_of_big_int aux4__6 (aux4_first + n * ?L) ?L =
    ?x ^ nat (2 * n + 1) * ?R mod ?m"
  proof (cases "n = loop__1__h")
    case False
    have "num_of_big_int aux4__6 (aux4_first + n * ?L) ?L =
      num_of_big_int aux4 (aux4_first + n * ?L) ?L"
    proof (intro num_of_lint_ext ballI)
      fix j
      assume j: "j \<in> {aux4_first + n * ?L..<aux4_first + n * ?L + ?L}"
      from n `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
      have "n * ?L \<le> (2 ^ nat k - 1) * ?L"
        by simp
      with `a_first < a_last`
      have "n * ?L + ?L \<le> 2 ^ nat k * ?L"
        by (simp add: sign_simps)
      with j `aux4_first + (2 ^ nat k * ?L - 1) \<le>
        aux4__index__subtype__1__last`
      have "j \<le> aux4__index__subtype__1__last" by simp
      moreover from n `a_first < a_last`
      have "aux4_first \<le> aux4_first + n * ?L"
        by (simp add: mult_nonneg_nonneg)
      with j `aux4__index__subtype__1__first \<le> aux4_first`
      have "aux4__index__subtype__1__first \<le> j"
        by simp
      moreover from n False have "n \<le> loop__1__h - 1" by simp
      with `a_first < a_last` have "n * ?L + ?L \<le> (loop__1__h - 1) * ?L + ?L"
        by simp
      with j have "j < aux4_first + loop__1__h * ?L"
        by (simp add: left_diff_distrib)
      ultimately have "aux4__6 j = aux4 j" using copy
        by simp
      then show "aux4__6 j =
        aux4 (aux4_first + n * ?L + (j - (aux4_first + n * ?L)))"
        by simp
    qed
    with n False `\<forall>n. _ \<longrightarrow> num_of_big_int aux4 _ _ = _`
    show ?thesis by simp
  next
    case True
    have "num_of_big_int aux4__6 (aux4_first + n * ?L) ?L =
      num_of_big_int a__5 a_first ?L"
    proof (intro num_of_lint_ext ballI)
      fix j
      assume j: "j \<in> {aux4_first + n * ?L..<aux4_first + n * ?L + ?L}"
      from n `loop__1__h \<le> 2 ^ nat k - 1` `a_first < a_last`
      have "n * ?L \<le> (2 ^ nat k - 1) * ?L"
        by simp
      with `a_first < a_last`
      have "n * ?L + ?L \<le> 2 ^ nat k * ?L"
        by (simp add: sign_simps)
      with j `aux4_first + (2 ^ nat k * ?L - 1) \<le>
        aux4__index__subtype__1__last`
      have "j \<le> aux4__index__subtype__1__last" by simp
      moreover from n `a_first < a_last`
      have "aux4_first \<le> aux4_first + n * ?L"
        by (simp add: mult_nonneg_nonneg)
      with j `aux4__index__subtype__1__first \<le> aux4_first`
      have "aux4__index__subtype__1__first \<le> j"
        by simp
      ultimately show "aux4__6 j =
        a__5 (a_first + (j - (aux4_first + n * (a_last - a_first + 1))))"
        using copy True j
        by (simp add: sign_simps)
    qed
    with True
      `num_of_big_int a__5 _ _ = _`
      `num_of_big_int aux2 _ _ = _`
      `\<forall>n. _ \<longrightarrow> num_of_big_int aux4 _ _ = _`
      `1 \<le> loop__1__h`
    show ?thesis
      by (simp add: mont_mult_eq [OF Base_inv])
        (simp add: power_Suc [symmetric]
           Suc_nat_eq_nat_zadd1 add_ac mult_ac)
  qed
qed

spark_vc procedure_mont_exp_window_17
proof -
  from
    `num_of_big_int aux3 _ _ = _` `e_first \<le> e_last`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first` `e_last \<le> e__index__subtype__1__last`
  show ?C1
    by (simp only: nat_mult_distrib)
      (simp add: sdiv_pos_pos power_mult mult.commute [of _ 32]
         num_of_lint_lower num_of_lint_upper div_pos_pos_trivial
         del: num_of_lint_sum)

  have "(0::int) < 2 ^ nat k" by simp
  with `2 ^ nat k < 2` have "(2::int) ^ nat k = 1" by (simp (no_asm_simp))
  with `num_of_big_int aux4 _ _ = _` show ?C2
    by auto
qed

spark_vc procedure_mont_exp_window_18
  using
    `num_of_big_int aux3 _ _ = _` `e_first \<le> e_last`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first` `e_last \<le> e__index__subtype__1__last`
  by (simp only: nat_mult_distrib)
    (simp add: sdiv_pos_pos power_mult mult.commute [of _ 32]
       num_of_lint_lower num_of_lint_upper div_pos_pos_trivial
       del: num_of_lint_sum)

spark_vc procedure_mont_exp_window_19
  using
    `i < (e_last - e_first + 1) * 32 mod _`
    `0 \<le> s`
  by simp

spark_vc procedure_mont_exp_window_20
proof -
  from
    `e__index__subtype__1__first \<le> e_first`
    `0 \<le> i`
  show ?C1 by (simp add: sdiv_pos_pos)
  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last`
    `e_last \<le> e__index__subtype__1__last`
    `0 \<le> i`
  show ?C2
    by (simp add: sdiv_pos_pos mod_pos_pos_trivial)
qed

spark_vc procedure_mont_exp_window_24
proof -
  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last`
  have i: "int (nat i) < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial)
  from
    `e (e_first + i sdiv 32) AND 2 ^ nat (i mod 32) \<noteq> 0`
    `bounds _ _ _ _ e`
    `0 \<le> i`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  show ?thesis
    by (simp add: sdiv_pos_pos num_of_lint_lower AND_div_mod [symmetric] mod_eq_1
      num_of_lint_AND_32 [OF i] zdiv_int nat_mod_distrib)
qed

spark_vc procedure_mont_exp_window_25
proof -
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"

  have "?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j < 2 ^ nat j"
    by simp
  also from `j \<le> k` `k \<le> 30`
  have "nat j \<le> 30" by simp
  then have "(2::int) ^ nat j \<le> 2 ^ 30"
    by (rule power_increasing) simp
  finally have e: "?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j * 2 < Base"
    by simp

  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last` `0 \<le> s` `s < j`
  have i: "int (nat (i - j)) < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial)

  from `lsc__types__shl32 w (j - s) = w * 2 ^ nat (j - s) mod Base`
  have "(lsc__types__shl32 w (j - s) OR 1) * 2 ^ nat (j + 1 - j - 1) =
    w * 2 ^ nat (j - s) mod Base OR 1"
    by simp
  also from `s < j` `0 \<le> s`
  have "(2::int) ^ nat (j - s) = 2 ^ nat (j - s - 1) * 2 ^ 1"
    by (simp only: power_add [symmetric]) (simp del: power.simps)
  also from
    `w * 2 ^ nat (j - s - 1) = _`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "w * (2 ^ nat (j - s - 1) * 2 ^ 1) =
    ?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j * 2"
    by (simp add: sdiv_pos_pos num_of_lint_lower)
  also from e have "\<dots> mod Base OR 1 =
    ?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j * 2 + 1"
    by (simp add: mod_pos_pos_trivial OR_plus1)
  also from `0 \<le> s` `s < j` `j \<le> i` have "\<dots> =
    (?e div 2 ^ nat (i - j) div 2 * 2 + 1) mod (2 ^ nat (j + 1))"
    by (simp add: mod_mult_add
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute [of 2])
  also from i `j \<le> i`
    `e (e_first + (i - j) sdiv 32) AND 2 ^ nat ((i - j) mod 32) \<noteq> 0`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "?e AND 2 ^ nat (i - j) \<noteq> 0"
    by (simp add: num_of_lint_AND_32 sdiv_pos_pos zdiv_int nat_mod_distrib
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (i - j) div 2 * 2 + 1 =
    ?e div 2 ^ nat (i - j) div 2 * 2 + ?e div 2 ^ nat (i - j) mod 2"
    by (simp add: AND_div_mod)
  finally show ?C1
    using
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos num_of_lint_lower)

  show ?C2
    by (simp add: AND_mod [where n=1, simplified, symmetric])
qed

spark_vc procedure_mont_exp_window_26
proof -
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"

  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last` `0 \<le> s` `s < j`
  have i: "int (nat (i - j)) < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial)

  from `s < j` `0 \<le> s`
  have "(2::int) ^ nat (j + 1 - s - 1) = 2 ^ nat (j - s - 1) * 2 ^ 1"
    by (simp only: power_add [symmetric]) (simp del: power.simps)
  then have "w * 2 ^ nat (j + 1 - s - 1) = w * 2 ^ nat (j - s - 1) * 2"
    by simp
  also note `w * 2 ^ nat (j - s - 1) = ?e sdiv 2 ^ nat (i - (j - 1)) mod 2 ^ nat j`
  also from `0 \<le> s` `s < j` `j \<le> i`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "?e sdiv 2 ^ nat (i - (j - 1)) mod 2 ^ nat j * 2 =
    (?e div 2 ^ nat (i - j) div 2 * 2) mod (2 ^ nat (j + 1))"
    by (simp add:
      trans [OF diff_diff_eq2 diff_add_eq [symmetric]]
      zdiv_zmult2_eq [symmetric] nat_add_distrib mult.commute
      sdiv_pos_pos num_of_lint_lower)
  also from i `j \<le> i`
    `e (e_first + (i - j) sdiv 32) AND 2 ^ nat ((i - j) mod 32) = 0`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "?e AND 2 ^ nat (i - j) = 0"
    by (simp add: num_of_lint_AND_32 sdiv_pos_pos zdiv_int nat_mod_distrib
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat (i - j) div 2 * 2 =
    ?e div 2 ^ nat (i - j) div 2 * 2 + ?e div 2 ^ nat (i - j) mod 2"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos num_of_lint_lower)
qed

spark_vc procedure_mont_exp_window_28
proof -
  from
    `e__index__subtype__1__first \<le> e_first`
    `j \<le> i`
  show ?C1 by (simp add: sdiv_pos_pos)
  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last` `0 \<le> s` `s < j`
    `e_last \<le> e__index__subtype__1__last`
    `j \<le> i`
  show ?C2
    by (simp add: mod_pos_pos_trivial sdiv_pos_pos)
qed

spark_vc procedure_mont_exp_window_37
proof -
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"

  from
    `w * 2 ^ nat (j - s - 1) = ?e sdiv 2 ^ nat (i - (j - 1)) mod 2 ^ nat j` [symmetric]
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "w * 2 ^ nat (j - s - 1) =
    (?e div 2 ^ nat (i - (j - 1)) -
     ?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j mod 2 ^ nat (j - s - 1))
      mod 2 ^ nat j"
    by (simp add: sdiv_pos_pos num_of_lint_lower)
  also from `s < j` `0 \<le> s` `j \<le> i + 1`
  have "?e div 2 ^ nat (i - (j - 1)) -
    ?e div 2 ^ nat (i - (j - 1)) mod 2 ^ nat j mod 2 ^ nat (j - s - 1) =
    ?e div 2 ^ nat (i - s) * 2 ^ nat (j - s - 1)"
    by (simp add: mod_mod_cancel le_imp_power_dvd
      mod_div_equality' [symmetric] zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric])
  also from `s < j` `0 \<le> s`
  have "?e div 2 ^ nat (i - s) * 2 ^ nat (j - s - 1) mod 2 ^ nat j =
    ?e div 2 ^ nat (i - s) mod 2 ^ nat (s + 1) * 2 ^ nat (j - s - 1)"
    by (simp add: mult_mod_left power_add [symmetric] nat_add_distrib [symmetric])
  finally show ?C1
    using
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos num_of_lint_lower)

  from `s < j` `j \<le> i + 1`
  show ?C2 by simp
qed

spark_vc procedure_mont_exp_window_41
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `\<forall>i. _ \<longrightarrow> (_ \<longrightarrow> _) \<and> (_ \<longrightarrow> _)`
    `aux3__index__subtype__1__first \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> aux3__index__subtype__1__last`
  have "num_of_big_int aux3__8 aux3_first ?L =
    num_of_big_int a__7 a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  moreover from `1 \<le> loop__4__h`
  have "nat loop__4__h = nat (loop__4__h - 1) + 1"
    by simp
  ultimately show ?thesis
    by (simp add: mont_mult_eq [OF Base_inv]
      `num_of_big_int a__7 _ _ = _` `num_of_big_int aux3 _ _ = _`)
      (simp add: mult_ac nat_mult_distrib power_mult power2_eq_square
         power_mult_distrib)
qed

spark_vc procedure_mont_exp_window_45
proof -
  let ?L = "a_last - a_first + 1"
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"

  have "?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s < 2 ^ nat s"
    by simp
  also from `s \<le> k + 1`
  have "(2::int) ^ nat s \<le> 2 ^ nat (k + 1)"
    by simp
  with `0 \<le> k` have "(2::int) ^ nat s \<le> 2 * 2 ^ nat k"
    by (simp add: nat_add_distrib)
  finally have "?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 < 2 ^ nat k"
    by (simp add: sdiv_pos_pos)
  with `a_first < a_last`
  have "?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 * ?L <
    2 ^ nat k * ?L"
    by simp
  with
    `aux4_first + (2 ^ nat k * (a_last - a_first + 1) - 1) \<le>
       aux4__index__subtype__1__last`
    `lsc__types__shr32 _ 1 = _`
  show ?C3 by simp
  with `aux4__index__subtype__1__last \<le> 2147483647`
  show ?C1 by simp
  with `0 \<le> aux4_first` show ?C7 by simp
  from `a_first < a_last`
  have "0 \<le> ?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 * ?L"
    by (simp add: sdiv_pos_pos pos_imp_zdiv_nonneg_iff mult_nonneg_nonneg)
  with
    `lsc__types__shr32 _ 1 = _`
    `aux4__index__subtype__1__first \<le> aux4_first`
  show ?C2 by simp
  with `a_first < a_last` show ?C4 by simp
  from `?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 < 2 ^ nat k`
    `a_first < a_last`
  have "?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 * ?L \<le>
    (2 ^ nat k - 1) * ?L"
    by simp
  with
    `aux4_first + (2 ^ nat k * ?L - 1) \<le> aux4__index__subtype__1__last`
    `lsc__types__shr32 _ 1 = _`
  show ?C5 by (simp add: left_diff_distrib)
  from
    `\<forall>n. _ \<longrightarrow> num_of_big_int aux4 _ _ = _`
    `?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 < 2 ^ nat k`
    `lsc__types__shr32 _ 1 = _`
    `1 < num_of_big_int m m_first ?L`
  show ?C6
    by (simp add: sdiv_pos_pos pos_imp_zdiv_nonneg_iff)
  from `k \<le> 30` have "(2::int) ^ nat k \<le> 2 ^ nat 30"
    by (simp only: nat_mono power_increasing)
  with
    `?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 < 2 ^ nat k`
    `lsc__types__shr32 _ 1 = _`
  show ?C8 by simp
qed

spark_vc procedure_mont_exp_window_51
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"
  let ?x = "num_of_big_int x x_first ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `0 \<le> e_first`
    `e_last \<le> 2147483647`
    `i < (e_last - e_first + 1) * 32 mod _`
    `e_first \<le> e_last`
  have i: "i < 32 * (e_last - e_first + 1)"
    by (simp add: mod_pos_pos_trivial)

  from
    `\<forall>i. _ \<longrightarrow> (_ \<longrightarrow> _) \<and> (_ \<longrightarrow> _)`
    `aux3__index__subtype__1__first \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> aux3__index__subtype__1__last`
  have "num_of_big_int aux3__12 aux3_first ?L =
    num_of_big_int a__11 a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  with
    `num_of_big_int a__11 _ _ = _`
    `num_of_big_int aux3 _ _ = _`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
    `0 \<le> i`
  have "num_of_big_int aux3__12 aux3_first ?L =
    ?x ^ nat ((?e div 2 ^ nat i div 2) * 2) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      sdiv_pos_pos num_of_lint_lower pos_imp_zdiv_nonneg_iff)
      (simp add: nat_add_distrib zdiv_zmult2_eq [symmetric] mult_ac)
  also have "(?e div 2 ^ nat i div 2) * 2 =
    ?e div 2 ^ nat i - ?e div 2 ^ nat i mod 2"
    by (simp add: mod_div_equality')
  also from `0 \<le> i` i
    `e (e_first + i sdiv 32) AND 2 ^ nat (i mod 32) = 0`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "?e AND 2 ^ nat i = 0"
    by (simp add: num_of_lint_AND_32 sdiv_pos_pos zdiv_int nat_mod_distrib
      del: num_of_lint_sum)
  then have "?e div 2 ^ nat i mod 2 = 0"
    by (simp add: AND_div_mod)
  finally show ?thesis
    using
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos num_of_lint_lower)
qed

spark_vc procedure_mont_exp_window_53
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"
  let ?e = "num_of_big_int e e_first (e_last - e_first + 1)"
  let ?x = "num_of_big_int x x_first ?L"
  let ?R = "Base ^ nat ?L"

  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `\<forall>i. _ \<longrightarrow> (_ \<longrightarrow> _) \<and> (_ \<longrightarrow> _)`
    `aux3__index__subtype__1__first \<le> aux3_first`
    `aux3_first + (a_last - a_first) \<le> aux3__index__subtype__1__last`
  have "num_of_big_int aux3__10 aux3_first ?L =
    num_of_big_int a__9 a_first ?L"
    by (simp add: num_of_lint_ext add_diff_eq)
  also note `num_of_big_int a__9 _ _ = _`
  also note `num_of_big_int aux3 _ _ = _`
  also note `lsc__types__shr32 _ 1 = _`
  also from
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "?x ^ nat (?e sdiv 2 ^ nat (i + 1) * 2 ^ nat s) * ?R mod ?m *
    num_of_big_int aux4
      (aux4_first + ?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s sdiv 2 * ?L) ?L *
    minv ?m Base ^ nat ?L mod ?m =
    ?x ^ nat (?e div 2 ^ nat (i + 1) * 2 ^ nat s) * ?R mod ?m *
    num_of_big_int aux4
      (aux4_first + ?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2 * ?L) ?L *
    minv ?m Base ^ nat ?L mod ?m"
    by (simp add: sdiv_pos_pos num_of_lint_lower)
  also {
    have "?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s < 2 ^ nat s"
      by simp
    also from `s \<le> k + 1`
    have "(2::int) ^ nat s \<le> 2 ^ nat (k + 1)"
      by simp
    with `0 \<le> k` have "(2::int) ^ nat s \<le> 2 * 2 ^ nat k"
      by (simp add: nat_add_distrib)
    finally have "?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2 < 2 ^ nat k"
      by simp
    with
      `\<forall>n. _ \<longrightarrow> num_of_big_int aux4 _ _ = _`
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    have " num_of_big_int aux4
      (aux4_first + ?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2 * ?L) ?L =
      ?x ^ nat (2 * (?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2) + 1) *
      ?R mod ?m"
      by (simp add: pos_imp_zdiv_nonneg_iff num_of_lint_lower)
  } also from
    `?e sdiv 2 ^ nat (i - (s - 1)) mod 2 ^ nat s mod 2 = 1`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have "2 * (?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2) + 1 =
    2 * (?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s div 2) +
    ?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s mod 2"
    by (simp add: sdiv_pos_pos num_of_lint_lower)
  also have "\<dots> = ?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s"
    by simp
  also from `0 \<le> s` `s \<le> i + 1`
  have "?e div 2 ^ nat (i + 1) =
    ?e div 2 ^ nat (i - (s - 1)) div 2 ^ nat s"
    by (simp add: zdiv_zmult2_eq [symmetric]
      power_add [symmetric] nat_add_distrib [symmetric])
  also from
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  have
    "?x ^ nat (?e div 2 ^ nat (i - (s - 1)) div 2 ^ nat s * 2 ^ nat s) * ?R mod ?m *
     (?x ^ nat (?e div 2 ^ nat (i - (s - 1)) mod 2 ^ nat s) * ?R mod ?m) *
     minv ?m Base ^ nat ?L mod ?m =
     ?x ^ nat (?e div 2 ^ nat (i - (s - 1))) * ?R mod ?m"
    by (simp add: mont_mult_eq [OF Base_inv]
      power_add [symmetric] nat_add_distrib [symmetric]
      pos_imp_zdiv_nonneg_iff num_of_lint_lower mult_nonneg_nonneg
      mod_div_equality)
  finally show ?thesis
    using
      `bounds _ _ _ _ e`
      `e__index__subtype__1__first \<le> e_first`
      `e_last \<le> e__index__subtype__1__last`
    by (simp add: sdiv_pos_pos num_of_lint_lower sign_simps)
qed

spark_vc procedure_mont_exp_window_57
proof -
  let ?L = "a_last - a_first + 1"
  let ?m = "num_of_big_int m m_first ?L"

  note m_inv = `(1 + m_inv * m m_first mod Base) mod Base = 0` [simplified]

  from `a_first < a_last` `1 < ?m`
  have Base_inv: "Base * minv ?m Base mod ?m = 1"
    by (simp only: lint_inv_mod [of m_inv m _ 32, simplified, OF m_inv])

  from
    `num_of_big_int a__13 _ _ = _`
    `num_of_big_int aux3 _ _ = _`
    `num_of_big_int aux1 _ _ = _`
  have "num_of_big_int a__13 a_first (a_last - a_first + 1) =
    num_of_big_int x x_first ?L ^
      nat (num_of_big_int e e_first (e_last - e_first + 1) sdiv 2 ^ nat (i - s + 1)) *
    (Base * minv ?m Base mod ?m) ^ nat ?L mod ?m"
    by (simp add: power_mult_distrib mult.assoc)
  with Base_inv `s \<le> i + 1` `i < s`
    `bounds _ _ _ _ e`
    `e__index__subtype__1__first \<le> e_first`
    `e_last \<le> e__index__subtype__1__last`
  show ?thesis by (simp add: sdiv_pos_pos num_of_lint_lower)
qed

spark_end

end
