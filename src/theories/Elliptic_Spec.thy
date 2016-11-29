theory Elliptic_Spec
imports
  LibSPARKcrypto
  Elliptic
  "~~/src/HOL/Number_Theory/Residues"
begin

setup {*
let
  val simplified = Attrib.thms >>
    (fn ths => Thm.rule_attribute ths (fn context =>
      Simplifier.asm_full_simplify (Context.proof_of context addsimps ths)));
in
  Attrib.setup @{binding my_simplified} simplified "simplified rule"
end
*}

context residues
begin

lemma res_diff_cong: "x mod m \<ominus> y mod m = (x - y) mod m"
  by (simp add: minus_eq res_neg_eq res_add_eq)

lemma res_of_nat_eq: "\<guillemotleft>n\<guillemotright>\<^sub>\<nat> = n mod m"
  by (induct n) (simp_all add: zero_cong one_cong res_add_eq)

lemma res_of_int_eq: "\<guillemotleft>i\<guillemotright> = i mod m"
  by (simp add: of_integer_def res_of_nat_eq res_neg_eq)

lemma res_pow_eq: "x (^) n = x ^ n mod m"
  by (induct n) (simp_all add: one_cong res_mult_eq mult.commute)

end

locale residues_prime_ell = residues_prime +
  assumes gt2: "2 < p"

sublocale residues_prime_ell < ell_field
  using gt2
  by unfold_locales (simp add: res_of_int_eq zero_cong)

lemma eq0_inv_iff:
  assumes "(b::int) * i mod m = 1"
  shows "(x * i mod m = 0) = (x mod m = 0)"
proof
  assume "x * i mod m = 0"
  then have "x * i mod m = 0 mod m" by simp
  then have "b * i mod m * x mod m = 0"
    by (drule_tac mod_mult_cong [OF refl, of _ _ _ b]) (simp add: mult_ac)
  then show "x mod m = 0" by (simp add: assms)
next
  assume "x mod m = 0"
  then have "x mod m = 0 mod m" by simp
  then show "x * i mod m = 0"
    by (drule_tac mod_mult_cong [OF _ refl, of _ _ _ i]) simp
qed

lemma eq0_inv_iff':
  assumes "(b::int) * i mod m = 1"
  shows "(x * i ^ n mod m = 0) = (x mod m = 0)"
proof (induct n)
  case (Suc n)
  have "(x * i ^ Suc n mod m = 0) = (x * i ^ n * i mod m = 0)"
    by (simp add: mult_ac)
  then show ?case
    by (simp add: eq0_inv_iff [OF assms] Suc)
qed simp

(**** Lsc__ec__point_double_spec ****)

definition point_double_spec :: "math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> bool"
where
  "point_double_spec m a x\<^sub>1 y\<^sub>1 z\<^sub>1 x\<^sub>2 y\<^sub>2 z\<^sub>2 =
     (let
        r = residue_ring (int_of_math_int m);
        a' = int_of_math_int a mod int_of_math_int m
      in cring.proj_eq r
        (cring.pdouble r a'
           (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1))
        (int_of_math_int x\<^sub>2, int_of_math_int y\<^sub>2, int_of_math_int z\<^sub>2))"

why3_consts
  Lsc__ec__point_double_spec.point_double_spec = point_double_spec

(**** Lsc__ec__point_add_spec ****)

definition point_add_spec :: "math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> bool"
where
  "point_add_spec m a x\<^sub>1 y\<^sub>1 z\<^sub>1 x\<^sub>2 y\<^sub>2 z\<^sub>2 x\<^sub>3 y\<^sub>3 z\<^sub>3 =
     (let
        r = residue_ring (int_of_math_int m);
        a' = int_of_math_int a mod int_of_math_int m
      in cring.proj_eq r
        (cring.padd r a'
           (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1)
           (int_of_math_int x\<^sub>2, int_of_math_int y\<^sub>2, int_of_math_int z\<^sub>2))
        (int_of_math_int x\<^sub>3, int_of_math_int y\<^sub>3, int_of_math_int z\<^sub>3))"

why3_consts
  Lsc__ec__point_add_spec.point_add_spec = point_add_spec

(**** Lsc__ec__point_mult_spec ****)

definition point_mult_spec :: "math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> bool"
where
  "point_mult_spec m a x\<^sub>1 y\<^sub>1 z\<^sub>1 e x\<^sub>2 y\<^sub>2 z\<^sub>2 =
     (let
        r = residue_ring (int_of_math_int m);
        a' = int_of_math_int a mod int_of_math_int m
      in
        2 < int_of_math_int m \<longrightarrow> prime (nat (int_of_math_int m)) \<longrightarrow>
        (\<forall>b. 0 \<le> b \<longrightarrow> b < int_of_math_int m \<longrightarrow>
         ell_field.nonsingular r a' b \<longrightarrow>
         cring.on_curvep r a' b
           (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1) \<longrightarrow>
         cring.proj_eq r
           (cring.ppoint_mult r a'
              (nat (int_of_math_int e))
              (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1))
           (int_of_math_int x\<^sub>2, int_of_math_int y\<^sub>2, int_of_math_int z\<^sub>2)))"

why3_consts
  Lsc__ec__point_mult_spec.point_mult_spec = point_mult_spec

(**** Lsc__ec__two_point_mult_spec ****)

definition two_point_mult_spec :: "math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow>
  math_int \<Rightarrow> math_int \<Rightarrow> math_int \<Rightarrow> bool"
where
  "two_point_mult_spec m a x\<^sub>1 y\<^sub>1 z\<^sub>1 e\<^sub>1 x\<^sub>2 y\<^sub>2 z\<^sub>2 e\<^sub>2 x\<^sub>3 y\<^sub>3 z\<^sub>3 =
     (let
        r = residue_ring (int_of_math_int m);
        a' = int_of_math_int a mod int_of_math_int m
      in
        2 < int_of_math_int m \<longrightarrow> prime (nat (int_of_math_int m)) \<longrightarrow>
        (\<forall>b. 0 \<le> b \<longrightarrow> b < int_of_math_int m \<longrightarrow>
         ell_field.nonsingular r a' b \<longrightarrow>
         cring.on_curvep r a' b
           (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1) \<longrightarrow>
         cring.on_curvep r a' b
           (int_of_math_int x\<^sub>2, int_of_math_int y\<^sub>2, int_of_math_int z\<^sub>2) \<longrightarrow>
         cring.proj_eq r
           (cring.padd r a'
              (cring.ppoint_mult r a'
                 (nat (int_of_math_int e\<^sub>1))
                 (int_of_math_int x\<^sub>1, int_of_math_int y\<^sub>1, int_of_math_int z\<^sub>1))
              (cring.ppoint_mult r a'
                 (nat (int_of_math_int e\<^sub>2))
                 (int_of_math_int x\<^sub>2, int_of_math_int y\<^sub>2, int_of_math_int z\<^sub>2)))
           (int_of_math_int x\<^sub>3, int_of_math_int y\<^sub>3, int_of_math_int z\<^sub>3)))"

why3_consts
  Lsc__ec__two_point_mult_spec.two_point_mult_spec = two_point_mult_spec

end
