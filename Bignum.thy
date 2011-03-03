theory Bignum
imports SPARK Facts GCD Mod_Simp
begin

primrec num_of_bool :: "bool \<Rightarrow> int"
where
  "num_of_bool False = 0"
| "num_of_bool True = 1"

lemma num_of_bool_split: "P (num_of_bool b) = ((b \<longrightarrow> P 1) \<and> (\<not> b \<longrightarrow> P 0))"
  by (cases b) simp_all

lemma num_of_bool_ge0: "0 \<le> num_of_bool b"
  by (simp split add: num_of_bool_split)

lemma num_of_bool_le1: "num_of_bool b \<le> 1"
  by (simp split add: num_of_bool_split)

definition num_of_lint :: "int \<Rightarrow> (int \<Rightarrow> int) \<Rightarrow> int \<Rightarrow> int \<Rightarrow> int" where
  "num_of_lint b A l i = (\<Sum>j=0..<i. b ^ nat j * A (l + j))"

lemma num_of_lint_0 [simp]: "num_of_lint b A l 0 = 0"
  by (simp add: num_of_lint_def)

lemma num_of_lint_1 [simp]: "num_of_lint b A l 1 = A l"
proof -
  have "{0..<1} = {0::int}" by auto
  then show ?thesis
    by (simp add: num_of_lint_def)
qed

lemma num_of_lint_sum [simp]:
  assumes "0 \<le> i" and "0 \<le> j"
  shows "num_of_lint b A l (i + j) =
    num_of_lint b A l i + b ^ nat i * num_of_lint b A (l + i) j"
proof -
  have inj: "inj_on (\<lambda>k. k + i) {0..<j}"
    by (rule inj_onI) simp
  from assms have "{0..<i + j} = {0..<i} \<union> {i..<i + j}"
    by (simp add: ivl_disj_un)
  with setsum_reindex [OF inj, of "\<lambda>k. b ^ nat k * A (l + k)"]
    image_add_int_atLeastLessThan [of i "i + j"] `0 \<le> i`
  show ?thesis
    by (simp add: num_of_lint_def setsum_Un_disjoint nat_add_distrib
      power_add setsum_right_distrib add_ac mult_ac)
qed

lemma num_of_lint_upper:
  assumes A: "\<forall>j\<in>{l..<l+i}. A j < b" and "0 \<le> b"
  shows "num_of_lint b A l i < b ^ nat i"
proof (cases "0 \<le> i")
  case True
  then show ?thesis using A
  proof (induct rule: int_ge_induct)
    case base
    show ?case by simp
  next
    case (step i)
    then have "A (l + i) \<le> b - 1" by simp
    moreover from `0 \<le> b` have "0 \<le> b ^ nat i" by simp
    ultimately have "b ^ nat i * A (l + i) \<le> b ^ nat i * (b - 1)"
      by (rule mult_left_mono)
    with `0 \<le> i` have "b ^ nat i * A (l + i) \<le> b ^ nat (i + 1) - b ^ nat i"
      by (simp add: nat_add_distrib sign_simps)
    moreover from step have "num_of_lint b A l i < b ^ nat i"
      by simp
    ultimately show ?case using `0 \<le> i` by simp
  qed
next
  case False then show ?thesis by (simp add: num_of_lint_def)
qed

lemma num_of_lint_lower:
  "0 \<le> b \<Longrightarrow> \<forall>j\<in>{l..<l+i}. 0 \<le> A j \<Longrightarrow> 0 \<le> num_of_lint b A l i"
  by (simp add: mult_nonneg_nonneg setsum_nonneg num_of_lint_def)

lemma num_of_lint_all0:
  assumes "\<forall>j\<in>{0..<i}. A (l + j) = 0"
  shows "num_of_lint b A l i = 0"
  using assms
  by (simp add: num_of_lint_def)

lemma num_of_lint_update_neutral [simp]:
  "l + i \<le> j \<Longrightarrow> num_of_lint b (A(j := x)) l i = num_of_lint b A l i"
  by (simp add: num_of_lint_def)

lemma num_of_lint_update_neutral' [simp]:
  "j < l \<Longrightarrow> num_of_lint b (A(j := x)) l i = num_of_lint b A l i"
  by (simp add: num_of_lint_def)

lemma num_of_lint_update [simp]:
  assumes "l \<le> j" and "j < l + i"
  shows "num_of_lint b (A(j := x)) l i =
    num_of_lint b A l i + b ^ nat (j - l) * (x - A j)"
proof -
  let ?i = "j - l + 1 + (i - (j - l) - 1)"
  have "num_of_lint b (A(j := x)) l i = num_of_lint b (A(j := x)) l ?i"
    by simp
  also from assms
  have "\<dots> = num_of_lint b A l (j - l) +
    b ^ nat (j - l) *
      (x + b * num_of_lint b A (j + 1) (i - (j - l) - 1))"
    by (simp only: num_of_lint_sum)
      (simp add: ring_distribs nat_add_distrib)
  also from assms
  have "\<dots> = num_of_lint b A l ?i + b ^ nat (j - l) * (x - A j)"
    by (simp only: num_of_lint_sum)
      (simp add: ring_distribs nat_add_distrib)
  finally show ?thesis by simp
qed

lemma num_of_lint_div: 
  assumes "0 \<le> i" and "0 \<le> A l" and "A l < b"
  shows "num_of_lint b A l (i + 1) div b = num_of_lint b A (l + 1) i"
  using assms
  by (simp only: add_commute [of i 1])
    (simp add: zdiv_mult_self div_pos_pos_trivial)

lemma num_of_lint_mod:
  assumes "1 \<le> i" and "0 \<le> A l" and "A l < b"
  shows "num_of_lint b A l i mod b = A l"
  using assms
  by (auto simp add: zle_iff_zadd)
    (simp add: mod_pos_pos_trivial)

lemma num_of_lint_mod_dvd:
  assumes "1 \<le> i" and "m dvd b"
  shows "num_of_lint b A l i mod m = A l mod m"
proof -
  from `1 \<le> i` obtain n where "i = 1 + int n"
    by (auto simp add: zle_iff_zadd)
  then have "num_of_lint b A l i mod m =
    (A l + b mod m * num_of_lint b A (l + 1) (int n)) mod m"
    by simp
  with `m dvd b` show ?thesis by (simp add: dvd_eq_mod_eq_0)
qed

lemma odd_coprime:
  assumes "(m::int) mod 2 = 1"
  shows "coprime m (2 ^ n)"
proof (rule coprime_exp_int)
  from assms gcd_red_int [of m 2]
  show "coprime m 2" by simp
qed

lemma inv_imp_odd:
  assumes "0 < n"
  and "((1::int) + m' * m) mod 2 ^ n = 0"
  shows "m mod 2 = 1"
proof (rule ccontr)
  assume "m mod 2 \<noteq> 1"
  then have "m mod 2 = 0" by simp
  then obtain k where "m = k * 2" by auto
  moreover from `0 < n` obtain n' where "n = Suc n'"
    by (cases n) simp_all
  moreover note `(1 + m' * m) mod 2 ^ n = 0`
  moreover have "0 \<le> m' * k mod 2 ^ n'" by simp
  ultimately show False
    by (simp add: zmod_zmult2_eq mod_add_eq [of 1 "m' * (k * 2)"])
qed

definition minv :: "int \<Rightarrow> int \<Rightarrow> int" where
  "minv m x = fst (bezw (nat x) (nat m)) mod m"

lemma minv_is_inverse:
  assumes "coprime x m" and "0 < x" and "1 < m"
  shows "(x * minv m x) mod m = 1"
  unfolding minv_def
proof -
  let ?b = "bezw (nat x) (nat m)"
  from `coprime x m` `0 < x` `1 < m`
  have "int (gcd (nat x) (nat m)) = 1"
    by (simp add: transfer_int_nat_gcd [symmetric])
  with `0 < x` `1 < m`
  have "x * fst ?b + snd ?b * m = 1"
    by (simp add: bezw_aux [symmetric] mult_commute)
  then have "(x * fst ?b + snd ?b * m) mod m = 1 mod m" by simp
  with `1 < m` show "x * (fst ?b mod m) mod m = 1"
    by (simp add: mod_add_eq [of "x * fst ?b" "snd ?b * m"]
      mod_mult_right_eq [symmetric] mod_pos_pos_trivial)
qed

lemma inv_div:
  assumes "(n * n') mod (m::int) = 1"
  and "k mod n = 0"
  shows "(k div n) mod m = (k * n') mod m"
proof -
  from `k mod n = 0` mod_div_equality [of k n]
  have "(k div n * n) * n' mod m = (k * n') mod m"
    by simp
  then have "((k div n) * ((n * n') mod m)) mod m = (k * n') mod m"
    by (simp add: mod_mult_right_eq [symmetric]) (simp add: mult_assoc)
  with `(n * n') mod m = 1` show ?thesis by simp
qed

abbreviation Base :: int where
  "Base \<equiv> 4294967296"

lemmas [simp] = zle_diff1_eq [of _ Base, simplified]

lemma pow_simp: "0 \<le> b \<Longrightarrow> (a::int) ^ nat (b * c) = (a ^ nat b) ^ nat c"
  by (simp add: nat_mult_distrib zpower_zpower)

lemmas pow_simp_Base = pow_simp [of 32 2, simplified]

abbreviation
  "num_of_big_int \<equiv> num_of_lint Base"

spark_proof_functions
  num_of_big_int = num_of_big_int
  num_of_boolean = num_of_bool
  inverse = minv

end
