theory Bignum
imports SPARK
begin

primrec num_of_bool :: "bool \<Rightarrow> int"
where
  "num_of_bool False = 0"
| "num_of_bool True = 1"

lemma num_of_bool_split: "P (num_of_bool b) = ((b \<longrightarrow> P 1) \<and> (\<not> b \<longrightarrow> P 0))"
  by (cases b) simp_all

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

lemma num_of_lint_update [simp]:
  "l + i \<le> j \<Longrightarrow> num_of_lint b (A(j := x)) l i = num_of_lint b A l i"
  by (simp add: num_of_lint_def)

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

end
