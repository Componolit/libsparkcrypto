theory Bignum
imports SPARK GCD Mod_Simp
begin

subsection {* Coercing booleans to integers *}

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


subsection {* Big numbers *}

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

lemma num_of_lint_expand:
  "0 < i \<Longrightarrow> num_of_lint b A l i = A l + b * num_of_lint b A (l + 1) (i - 1)"
  using num_of_lint_sum [of 1 "i - 1"]
  by simp

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

lemma num_of_lint_ext:
  "\<forall>j\<in>{l..<l+i}. A j = B (m + (j - l)) \<Longrightarrow>
   num_of_lint b A l i = num_of_lint b B m i"
  by (simp add: num_of_lint_def)

lemma num_of_lint_equals_iff:
  assumes "\<forall>j\<in>{l..<l+i}. 0 \<le> A j \<and> A j < b"
  and "\<forall>j\<in>{m..<m+i}. 0 \<le> B j \<and> B j < b"
  and "0 < b"
  shows "(num_of_lint b A l i = num_of_lint b B m i) =
    (\<forall>j\<in>{l..<l+i}. A j = B (m + (j - l)))"
proof
  assume eq: "num_of_lint b A l i = num_of_lint b B m i"
  show "\<forall>j\<in>{l..<l + i}. A j = B (m + (j - l))"
  proof
    fix j
    assume "j \<in> {l..<l + i}"
    then have j: "l \<le> j" "j < l + i"
      by simp_all
    have "num_of_lint b A l (j - l + 1 + (i - j + l - 1)) =
      num_of_lint b A l i"
      by simp
    also note eq
    also have "num_of_lint b B m i =
      num_of_lint b B m (j - l + 1 + (i - j + l - 1))"
      by simp
    finally have "num_of_lint b A l (j - l) + b ^ nat (j - l) * A j +
      b ^ nat (j - l + 1) * num_of_lint b A (j + 1) (i - j + l - 1) =
      num_of_lint b B m (j - l) + b ^ nat (j - l) * B (m + (j - l)) +
      b ^ nat (j - l + 1) *
      num_of_lint b B (m + (j - l + 1)) (i - j + l - 1)"
      (is "?x + ?y + ?z = ?x' + ?y' + ?z'" is "?l = ?r")
      using j
      by (simp only: num_of_lint_sum num_of_lint_1) simp
    then have "?l div b ^ nat (j - l) mod b = ?r div b ^ nat (j - l) mod b"
      by simp
    then show "A j = B (m + (j - l))" using j assms
      apply (simp add:
        zdiv_zadd1_eq [of "?x + ?y" ?z] zdiv_zadd1_eq [of ?x ?y]
        zdiv_zadd1_eq [of "?x' + ?y'" ?z'] zdiv_zadd1_eq [of ?x' ?y'])
      by (simp add: nat_add_distrib mod_pos_pos_trivial div_pos_pos_trivial
        num_of_lint_lower num_of_lint_upper)
  qed
next
  assume "\<forall>j\<in>{l..<l + i}. A j = B (m + (j - l))"
  then show "num_of_lint b A l i = num_of_lint b B m i"
    by (rule num_of_lint_ext)
qed


subsection {* Number theory *}

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
    by (simp add: mod_pos_pos_trivial)
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

lemma lint_inv_mod:
  assumes m_inv: "(1 + m_inv * m l) mod 2 ^ n = 0"
  and "0 < n" "1 \<le> i" "1 < num_of_lint (2 ^ n) m l i"
  shows "2 ^ n * minv (num_of_lint (2 ^ n) m l i) (2 ^ n) mod
    num_of_lint (2 ^ n) m l i = 1"
    (is "?B * _ mod ?m = 1")
proof -
  from inv_imp_odd [OF `0 < n` m_inv] `1 \<le> i` `0 < n`
  have "?m mod 2 = 1" by (simp add: num_of_lint_mod_dvd del: num_of_lint_sum)
  then have "coprime ?m ?B" by (rule odd_coprime)
  with `1 < ?m` show ?thesis
    by (simp add: minv_is_inverse gcd_commute_int)
qed


subsection {* Bit vectors *}

lemma Bit_mult2: "2 * i = i BIT 0"
  by (simp add: Bit_def)

lemma AND_div_mod: "((x::int) AND 2 ^ n = 0) = (x div 2 ^ n mod 2 = 0)"
proof (induct n arbitrary: x)
  case 0
  from AND_mod [of _ 1]
  show ?case by simp
next
  case (Suc n)
  show ?case
  proof (cases x rule: bin_exhaust)
    case (1 y b)
    then have "(x AND 2 ^ Suc n = 0) = (y AND 2 ^ n = 0)"
      by (simp add: Bit_mult2 del: BIT_B0_eq_Bit0)
        (simp add: Bit0_def [of "y AND 2 ^ n"])
    moreover have "bitval b div 2 = (0::int)"
      by (cases b) simp_all
    ultimately show ?thesis using Suc 1
      by (simp add: zdiv_zmult2_eq
        zdiv_zadd1_eq [of "2 * y" "bitval b" 2])
  qed
qed


subsection {* Proof function setup *}

abbreviation (parse) bounds :: "int \<Rightarrow> int \<Rightarrow> ('a::ord) \<Rightarrow> 'a \<Rightarrow> (int \<Rightarrow> 'a) \<Rightarrow> bool" where
  "bounds k l x y a \<equiv> \<forall>i. k \<le> i \<and> i \<le> l \<longrightarrow> x \<le> a i \<and> a i \<le> y"

abbreviation Base :: int where
  "Base \<equiv> 4294967296"

lemmas [simp] = zle_diff1_eq [of _ Base, simplified]

abbreviation
  "num_of_big_int \<equiv> num_of_lint Base"

spark_proof_functions
  lsc__bignum__num_of_big_int = num_of_big_int
  lsc__bignum__num_of_boolean = num_of_bool
  lsc__bignum__inverse = minv

end
