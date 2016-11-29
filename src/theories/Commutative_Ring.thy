(*  Author:     Bernhard Haeupler, Stefan Berghofer, and Amine Chaieb

Proving equalities in commutative rings done "right" in Isabelle/HOL.
*)

section {* Proving equalities in commutative rings *}

theory Commutative_Ring
imports
  Conv
  Algebra_Aux
  "~~/src/HOL/Library/Code_Target_Numeral"
begin

text {* Syntax of multivariate polynomials (pol) and polynomial expressions. *}

datatype pol =
    Pc int
  | Pinj nat pol
  | PX pol nat pol

datatype polex =
    Var nat
  | Const int
  | Add polex polex
  | Sub polex polex
  | Mul polex polex
  | Pow polex nat
  | Neg polex

text {* Interpretation functions for the shadow syntax. *}

context cring begin

definition in_carrier :: "'a list \<Rightarrow> bool" where
  "in_carrier xs = (\<forall>x\<in>set xs. x \<in> carrier R)"

lemma in_carrier_Nil: "in_carrier []"
  by (simp add: in_carrier_def)

lemma in_carrier_Cons: "x \<in> carrier R \<Longrightarrow> in_carrier xs \<Longrightarrow> in_carrier (x # xs)"
  by (simp add: in_carrier_def)

lemma drop_in_carrier [simp]: "in_carrier xs \<Longrightarrow> in_carrier (drop n xs)"
  using set_drop_subset [of n xs]
  by (auto simp add: in_carrier_def)

primrec head :: "'a list \<Rightarrow> 'a"
where
    "head [] = \<zero>"
  | "head (x # xs) = x"

lemma head_closed [simp]: "in_carrier xs \<Longrightarrow> head xs \<in> carrier R"
  by (cases xs) (simp_all add: in_carrier_def)

primrec Ipol :: "'a list \<Rightarrow> pol \<Rightarrow> 'a"
where
    "Ipol l (Pc c) = \<guillemotleft>c\<guillemotright>"
  | "Ipol l (Pinj i P) = Ipol (drop i l) P"
  | "Ipol l (PX P x Q) = Ipol l P \<otimes> head l (^) x \<oplus> Ipol (drop 1 l) Q"

lemma Ipol_Pc:
  "Ipol l (Pc 0) = \<zero>"
  "Ipol l (Pc 1) = \<one>"
  "Ipol l (Pc (numeral n)) = \<guillemotleft>numeral n\<guillemotright>"
  "Ipol l (Pc (- numeral n)) = \<ominus> \<guillemotleft>numeral n\<guillemotright>"
  by simp_all

lemma Ipol_closed [simp]:
  "in_carrier l \<Longrightarrow> Ipol l p \<in> carrier R"
  by (induct p arbitrary: l) simp_all

primrec Ipolex :: "'a list \<Rightarrow> polex \<Rightarrow> 'a"
where
    "Ipolex l (Var n) = head (drop n l)"
  | "Ipolex l (Const i) = \<guillemotleft>i\<guillemotright>"
  | "Ipolex l (Add P Q) = Ipolex l P \<oplus> Ipolex l Q"
  | "Ipolex l (Sub P Q) = Ipolex l P \<ominus> Ipolex l Q"
  | "Ipolex l (Mul P Q) = Ipolex l P \<otimes> Ipolex l Q"
  | "Ipolex l (Pow p n) = Ipolex l p (^) n"
  | "Ipolex l (Neg P) = \<ominus> Ipolex l P"

lemma Ipolex_Const:
  "Ipolex l (Const 0) = \<zero>"
  "Ipolex l (Const 1) = \<one>"
  "Ipolex l (Const (numeral n)) = \<guillemotleft>numeral n\<guillemotright>"
  by simp_all

end

text {* Create polynomial normalized polynomials given normalized inputs. *}

definition mkPinj :: "nat \<Rightarrow> pol \<Rightarrow> pol"
where
  "mkPinj x P =
    (case P of
      Pc c \<Rightarrow> Pc c
    | Pinj y P \<Rightarrow> Pinj (x + y) P
    | PX p1 y p2 \<Rightarrow> Pinj x P)"

definition mkPX :: "pol \<Rightarrow> nat \<Rightarrow> pol \<Rightarrow> pol"
where
  "mkPX P i Q =
    (case P of
      Pc c \<Rightarrow> if c = 0 then mkPinj 1 Q else PX P i Q
    | Pinj j R \<Rightarrow> PX P i Q
    | PX P2 i2 Q2 \<Rightarrow> if Q2 = Pc 0 then PX P2 (i + i2) Q else PX P i Q)"

text {* Defining the basic ring operations on normalized polynomials *}

function add :: "pol \<Rightarrow> pol \<Rightarrow> pol"  (infixl "\<langle>+\<rangle>" 65)
where
    "Pc a \<langle>+\<rangle> Pc b = Pc (a + b)"
  | "Pc c \<langle>+\<rangle> Pinj i P = Pinj i (P \<langle>+\<rangle> Pc c)"
  | "Pinj i P \<langle>+\<rangle> Pc c = Pinj i (P \<langle>+\<rangle> Pc c)"
  | "Pc c \<langle>+\<rangle> PX P i Q = PX P i (Q \<langle>+\<rangle> Pc c)"
  | "PX P i Q \<langle>+\<rangle> Pc c = PX P i (Q \<langle>+\<rangle> Pc c)"
  | "Pinj x P \<langle>+\<rangle> Pinj y Q =
      (if x = y then mkPinj x (P \<langle>+\<rangle> Q)
       else (if x > y then mkPinj y (Pinj (x - y) P \<langle>+\<rangle> Q)
         else mkPinj x (Pinj (y - x) Q \<langle>+\<rangle> P)))"
  | "Pinj x P \<langle>+\<rangle> PX Q y R =
      (if x = 0 then P \<langle>+\<rangle> PX Q y R
       else (if x = 1 then PX Q y (R \<langle>+\<rangle> P)
         else PX Q y (R \<langle>+\<rangle> Pinj (x - 1) P)))"
  | "PX P x R \<langle>+\<rangle> Pinj y Q =
      (if y = 0 then PX P x R \<langle>+\<rangle> Q
       else (if y = 1 then PX P x (R \<langle>+\<rangle> Q)
         else PX P x (R \<langle>+\<rangle> Pinj (y - 1) Q)))"
  | "PX P1 x P2 \<langle>+\<rangle> PX Q1 y Q2 =
      (if x = y then mkPX (P1 \<langle>+\<rangle> Q1) x (P2 \<langle>+\<rangle> Q2)
       else (if x > y then mkPX (PX P1 (x - y) (Pc 0) \<langle>+\<rangle> Q1) y (P2 \<langle>+\<rangle> Q2)
         else mkPX (PX Q1 (y - x) (Pc 0) \<langle>+\<rangle> P1) x (P2 \<langle>+\<rangle> Q2)))"
by pat_completeness auto
termination by (relation "measure (\<lambda>(x, y). size x + size y)") auto

function mul :: "pol \<Rightarrow> pol \<Rightarrow> pol"  (infixl "\<langle>*\<rangle>" 70)
where
    "Pc a \<langle>*\<rangle> Pc b = Pc (a * b)"
  | "Pc c \<langle>*\<rangle> Pinj i P =
      (if c = 0 then Pc 0 else mkPinj i (P \<langle>*\<rangle> Pc c))"
  | "Pinj i P \<langle>*\<rangle> Pc c =
      (if c = 0 then Pc 0 else mkPinj i (P \<langle>*\<rangle> Pc c))"
  | "Pc c \<langle>*\<rangle> PX P i Q =
      (if c = 0 then Pc 0 else mkPX (P \<langle>*\<rangle> Pc c) i (Q \<langle>*\<rangle> Pc c))"
  | "PX P i Q \<langle>*\<rangle> Pc c =
      (if c = 0 then Pc 0 else mkPX (P \<langle>*\<rangle> Pc c) i (Q \<langle>*\<rangle> Pc c))"
  | "Pinj x P \<langle>*\<rangle> Pinj y Q =
      (if x = y then mkPinj x (P \<langle>*\<rangle> Q)
       else
         (if x > y then mkPinj y (Pinj (x - y) P \<langle>*\<rangle> Q)
          else mkPinj x (Pinj (y - x) Q \<langle>*\<rangle> P)))"
  | "Pinj x P \<langle>*\<rangle> PX Q y R =
      (if x = 0 then P \<langle>*\<rangle> PX Q y R
       else
         (if x = 1 then mkPX (Pinj x P \<langle>*\<rangle> Q) y (R \<langle>*\<rangle> P)
          else mkPX (Pinj x P \<langle>*\<rangle> Q) y (R \<langle>*\<rangle> Pinj (x - 1) P)))"
  | "PX P x R \<langle>*\<rangle> Pinj y Q =
      (if y = 0 then PX P x R \<langle>*\<rangle> Q
       else
         (if y = 1 then mkPX (Pinj y Q \<langle>*\<rangle> P) x (R \<langle>*\<rangle> Q)
          else mkPX (Pinj y Q \<langle>*\<rangle> P) x (R \<langle>*\<rangle> Pinj (y - 1) Q)))"
  | "PX P1 x P2 \<langle>*\<rangle> PX Q1 y Q2 =
      mkPX (P1 \<langle>*\<rangle> Q1) (x + y) (P2 \<langle>*\<rangle> Q2) \<langle>+\<rangle>
        (mkPX (P1 \<langle>*\<rangle> mkPinj 1 Q2) x (Pc 0) \<langle>+\<rangle>
          (mkPX (Q1 \<langle>*\<rangle> mkPinj 1 P2) y (Pc 0)))"
by pat_completeness auto
termination by (relation "measure (\<lambda>(x, y). size x + size y)")
  (auto simp add: mkPinj_def split: pol.split)

text {* Negation*}
primrec neg :: "pol \<Rightarrow> pol"
where
    "neg (Pc c) = Pc (- c)"
  | "neg (Pinj i P) = Pinj i (neg P)"
  | "neg (PX P x Q) = PX (neg P) x (neg Q)"

text {* Subtraction *}
definition sub :: "pol \<Rightarrow> pol \<Rightarrow> pol"  (infixl "\<langle>-\<rangle>" 65)
where
  "sub P Q = P \<langle>+\<rangle> neg Q"

text {* Square for Fast Exponentiation *}
primrec sqr :: "pol \<Rightarrow> pol"
where
    "sqr (Pc c) = Pc (c * c)"
  | "sqr (Pinj i P) = mkPinj i (sqr P)"
  | "sqr (PX A x B) = mkPX (sqr A) (x + x) (sqr B) \<langle>+\<rangle>
      mkPX (Pc 2 \<langle>*\<rangle> A \<langle>*\<rangle> mkPinj 1 B) x (Pc 0)"

text {* Fast Exponentiation *}

fun pow :: "nat \<Rightarrow> pol \<Rightarrow> pol"
where
  pow_if [simp del]: "pow n P =
   (if n = 0 then Pc 1
    else if even n then pow (n div 2) (sqr P)
    else P \<langle>*\<rangle> pow (n div 2) (sqr P))"

lemma pow_simps [simp]:
  "pow 0 P = Pc 1"
  "pow (2 * n) P = pow n (sqr P)"
  "pow (Suc (2 * n)) P = P \<langle>*\<rangle> pow n (sqr P)"
  by (simp_all add: pow_if)

lemma even_pow: "even n \<Longrightarrow> pow n P = pow (n div 2) (sqr P)"
  by (erule evenE) simp

lemma odd_pow: "odd n \<Longrightarrow> pow n P = P \<langle>*\<rangle> pow (n div 2) (sqr P)"
  by (erule oddE) simp


text {* Normalization of polynomial expressions *}

primrec norm :: "polex \<Rightarrow> pol"
where
    "norm (Var n) =
       (if n = 0 then PX (Pc 1) 1 (Pc 0)
        else Pinj n (PX (Pc 1) 1 (Pc 0)))"
  | "norm (Const i) = Pc i"
  | "norm (Add P Q) = norm P \<langle>+\<rangle> norm Q"
  | "norm (Sub P Q) = norm P \<langle>-\<rangle> norm Q"
  | "norm (Mul P Q) = norm P \<langle>*\<rangle> norm Q"
  | "norm (Pow P n) = pow n (norm P)"
  | "norm (Neg P) = neg (norm P)"

context cring
begin

text {* mkPinj preserve semantics *}
lemma mkPinj_ci: "Ipol l (mkPinj a B) = Ipol l (Pinj a B)"
  by (induct B) (auto simp add: mkPinj_def algebra_simps)

text {* mkPX preserves semantics *}
lemma mkPX_ci: "in_carrier l \<Longrightarrow> Ipol l (mkPX A b C) = Ipol l (PX A b C)"
  by (cases A) (auto simp add: mkPX_def mkPinj_ci nat_pow_mult [symmetric] m_ac)

text {* Correctness theorems for the implemented operations *}

text {* Negation *}
lemma neg_ci: "in_carrier l \<Longrightarrow> Ipol l (neg P) = \<ominus> (Ipol l P)"
  by (induct P arbitrary: l) (auto simp add: minus_add l_minus)

text {* Addition *}
lemma add_ci: "in_carrier l \<Longrightarrow> Ipol l (P \<langle>+\<rangle> Q) = Ipol l P \<oplus> Ipol l Q"
proof (induct P Q arbitrary: l rule: add.induct)
  case (6 x P y Q)
  consider "x < y" | "x = y" | "x > y" by arith
  then show ?case
  proof cases
    case 1
    with 6 show ?thesis by (simp add: mkPinj_ci a_ac)
  next
    case 2
    with 6 show ?thesis by (simp add: mkPinj_ci)
  next
    case 3
    with 6 show ?thesis by (simp add: mkPinj_ci)
  qed
next
  case (7 x P Q y R)
  consider "x = 0" | "x = 1" | "x > 1" by arith
  then show ?case
  proof cases
    case 1
    with 7 show ?thesis by simp
  next
    case 2
    with 7 show ?thesis by (simp add: a_ac)
  next
    case 3
    with 7 show ?thesis by (cases x) (simp_all add: a_ac)
  qed
next
  case (8 P x R y Q)
  then show ?case by (simp add: a_ac)
next
  case (9 P1 x P2 Q1 y Q2)
  consider "x = y" | d where "d + x = y" | d where "d + y = x"
    by atomize_elim arith
  then show ?case
  proof cases
    case 1
    with 9 show ?thesis by (simp add: mkPX_ci r_distr a_ac m_ac)
  next
    case 2
    with 9 show ?thesis by (auto simp add: mkPX_ci nat_pow_mult [symmetric] r_distr a_ac m_ac)
  next
    case 3
    with 9 show ?thesis by (auto simp add: nat_pow_mult [symmetric] mkPX_ci r_distr a_ac m_ac)
  qed
qed (auto simp add: a_ac m_ac)

text {* Multiplication *}
lemma mul_ci: "in_carrier l \<Longrightarrow> Ipol l (P \<langle>*\<rangle> Q) = Ipol l P \<otimes> Ipol l Q"
  by (induct P Q arbitrary: l rule: mul.induct)
    (simp_all add: mkPX_ci mkPinj_ci a_ac m_ac r_distr add_ci nat_pow_mult [symmetric])

text {* Subtraction *}
lemma sub_ci: "in_carrier l \<Longrightarrow> Ipol l (P \<langle>-\<rangle> Q) = Ipol l P \<ominus> Ipol l Q"
  by (simp add: add_ci neg_ci sub_def minus_eq)
    
text {* Square *}
lemma sqr_ci: "in_carrier ls \<Longrightarrow> Ipol ls (sqr P) = Ipol ls P \<otimes> Ipol ls P"
  by (induct P arbitrary: ls)
    (simp_all add: add_ci mkPinj_ci mkPX_ci mul_ci l_distr r_distr
       a_ac m_ac nat_pow_mult [symmetric] of_int_2)

text {* Power *}
lemma pow_ci: "in_carrier ls \<Longrightarrow> Ipol ls (pow n P) = Ipol ls P (^) n"
proof (induct n arbitrary: P rule: less_induct)
  case (less k)
  consider "k = 0" | "k > 0" by arith
  then show ?case
  proof cases
    case 1
    then show ?thesis by simp
  next
    case 2
    then have "k div 2 < k" by arith
    with less have *: "Ipol ls (pow (k div 2) (sqr P)) = Ipol ls (sqr P) (^) (k div 2)"
      by simp
    show ?thesis
    proof (cases "even k")
      case True
      with * `in_carrier ls` show ?thesis
        by (simp add: even_pow sqr_ci nat_pow_distr nat_pow_mult
          mult_2 [symmetric] even_two_times_div_two)
    next
      case False
      with * `in_carrier ls` show ?thesis
        by (simp add: odd_pow mul_ci sqr_ci nat_pow_distr nat_pow_mult
          mult_2 [symmetric] trans [OF nat_pow_Suc m_comm, symmetric])
    qed
  qed
qed

text {* Normalization preserves semantics  *}
lemma norm_ci: "in_carrier l \<Longrightarrow> Ipolex l Pe = Ipol l (norm Pe)"
  by (induct Pe) (simp_all add: add_ci sub_ci mul_ci neg_ci pow_ci)

text {* Reflection lemma: Key to the (incomplete) decision procedure *}
lemma norm_eq:
  assumes "in_carrier l"
  and "norm P1 = norm P2"
  shows "Ipolex l P1 = Ipolex l P2"
proof -
  from assms have "Ipol l (norm P1) = Ipol l (norm P2)" by simp
  with assms show ?thesis by (simp only: norm_ci)
qed

end


text {* Monomials *}

datatype mon =
    Mc int
  | Minj nat mon
  | MX nat mon

primrec (in cring)
  Imon :: "'a list \<Rightarrow> mon \<Rightarrow> 'a"
where
    "Imon l (Mc c) = \<guillemotleft>c\<guillemotright>"
  | "Imon l (Minj i M) = Imon (drop i l) M"
  | "Imon l (MX x M) = Imon (drop 1 l) M \<otimes> head l (^) x"

lemma (in cring) Imon_closed [simp]:
  "in_carrier l \<Longrightarrow> Imon l m \<in> carrier R"
  by (induct m arbitrary: l) simp_all

definition
  mkMinj :: "nat \<Rightarrow> mon \<Rightarrow> mon" where
  "mkMinj i M = (case M of
       Mc c \<Rightarrow> Mc c
     | Minj j M \<Rightarrow> Minj (i + j) M
     | _ \<Rightarrow> Minj i M)"

definition
  Minj_pred :: "nat \<Rightarrow> mon \<Rightarrow> mon" where
  "Minj_pred i M = (if i = 1 then M else mkMinj (i - 1) M)"

primrec mkMX :: "nat \<Rightarrow> mon \<Rightarrow> mon"
where
  "mkMX i (Mc c) = MX i (Mc c)"
| "mkMX i (Minj j M) = (if j = 0 then mkMX i M else MX i (Minj_pred j M))"
| "mkMX i (MX j M) = MX (i + j) M"

lemma (in cring) mkMinj_correct:
  "Imon l (mkMinj i M) = Imon l (Minj i M)"
  by (simp add: mkMinj_def add.commute split add: mon.split)

lemma (in cring) Minj_pred_correct:
  "0 < i \<Longrightarrow> Imon (drop 1 l) (Minj_pred i M) = Imon l (Minj i M)"
  by (simp add: Minj_pred_def mkMinj_correct)

lemma (in cring) mkMX_correct:
  "in_carrier l \<Longrightarrow> Imon l (mkMX i M) = Imon l M \<otimes> head l (^) i"
  by (induct M) (simp_all add: Minj_pred_correct [simplified] nat_pow_mult [symmetric] m_ac split add: mon.split)

fun cfactor :: "pol \<Rightarrow> int \<Rightarrow> pol \<times> pol"
where
  "cfactor (Pc c') c = (Pc (c' mod c), Pc (c' div c))"
| "cfactor (Pinj i P) c =
     (let (R, S) = cfactor P c
      in (mkPinj i R, mkPinj i S))"
| "cfactor (PX P i Q) c =
     (let
        (R1, S1) = cfactor P c;
        (R2, S2) = cfactor Q c
      in (mkPX R1 i R2, mkPX S1 i S2))"

lemma (in cring) cfactor_correct:
  "in_carrier l \<Longrightarrow> Ipol l P = Ipol l (fst (cfactor P c)) \<oplus> \<guillemotleft>c\<guillemotright> \<otimes> Ipol l (snd (cfactor P c))"
proof (induct P c arbitrary: l rule: cfactor.induct)
  case (1 c' c)
  show ?case
    by (simp add: of_int_mult [symmetric] of_int_add [symmetric] del: of_int_mult)
next
  case (2 i P c)
  then show ?case
    by (simp add: mkPinj_ci split_beta)
next
  case (3 P i Q c)
  from 3(1) 3(2) [OF refl prod.collapse] 3(3)
  show ?case
    by (simp add: mkPX_ci r_distr a_ac m_ac split_beta)
qed

fun mfactor :: "pol \<Rightarrow> mon \<Rightarrow> pol \<times> pol"
where
  "mfactor P (Mc c) = (if c = 1 then (Pc 0, P) else cfactor P c)"
| "mfactor (Pc d) M = (Pc d, Pc 0)"
| "mfactor (Pinj i P) (Minj j M) =
     (if i = j then
        let (R, S) = mfactor P M
        in (mkPinj i R, mkPinj i S)
      else if i < j then
        let (R, S) = mfactor P (Minj (j - i) M)
        in (mkPinj i R, mkPinj i S)
      else (Pinj i P, Pc 0))"
| "mfactor (Pinj i P) (MX j M) = (Pinj i P, Pc 0)"
| "mfactor (PX P i Q) (Minj j M) =
     (if j = 0 then mfactor (PX P i Q) M
      else
        let
          (R1, S1) = mfactor P (Minj j M);
          (R2, S2) = mfactor Q (Minj_pred j M)
        in (mkPX R1 i R2, mkPX S1 i S2))"
| "mfactor (PX P i Q) (MX j M) =
     (if i = j then
        let (R, S) = mfactor P (mkMinj 1 M)
        in (mkPX R i Q, S)
      else if i < j then
        let (R, S) = mfactor P (MX (j - i) M)
        in (mkPX R i Q, S)
      else
        let (R, S) = mfactor P (mkMinj 1 M)
        in (mkPX R i Q, mkPX S (i - j) (Pc 0)))"

lemmas mfactor_induct = mfactor.induct
  [case_names Mc Pc_Minj Pc_MX Pinj_Minj Pinj_MX PX_Minj PX_MX]

lemma (in cring) mfactor_correct:
  "in_carrier l \<Longrightarrow>
   Ipol l P =
   Ipol l (fst (mfactor P M)) \<oplus>
   Imon l M \<otimes> Ipol l (snd (mfactor P M))"
proof (induct P M arbitrary: l rule: mfactor_induct)
  case (Mc P c)
  then show ?case
    by (simp add: cfactor_correct)
next
  case (Pc_Minj d i M)
  then show ?case
    by simp
next
  case (Pc_MX d i M)
  then show ?case
    by simp
next
  case (Pinj_Minj i P j M)
  then show ?case
    by (simp add: mkPinj_ci split_beta)
next
  case (Pinj_MX i P j M)
  then show ?case
    by simp
next
  case (PX_Minj P i Q j M)
  from PX_Minj(1,2) PX_Minj(3) [OF _ refl prod.collapse] PX_Minj(4)
  show ?case
    by (simp add: mkPX_ci Minj_pred_correct [simplified] r_distr a_ac m_ac split_beta)
next
  case (PX_MX P i Q j M)
  from `in_carrier l`
  have eq1: "(Imon (drop (Suc 0) l) M \<otimes> head l (^) (j - i)) \<otimes>
    Ipol l (snd (mfactor P (MX (j - i) M))) \<otimes> head l (^) i =
    Imon (drop (Suc 0) l) M \<otimes>
    Ipol l (snd (mfactor P (MX (j - i) M))) \<otimes>
    (head l (^) (j - i) \<otimes> head l (^) i)"
    by (simp add: m_ac)
  from `in_carrier l`
  have eq2: "(Imon (drop (Suc 0) l) M \<otimes> head l (^) j) \<otimes>
    (Ipol l (snd (mfactor P (mkMinj (Suc 0) M))) \<otimes> head l (^) (i - j)) =
    Imon (drop (Suc 0) l) M \<otimes>
    Ipol l (snd (mfactor P (mkMinj (Suc 0) M))) \<otimes>
    (head l (^) (i - j) \<otimes> head l (^) j)"
    by (simp add: m_ac)
  from PX_MX `in_carrier l` show ?case
    by (simp add: mkPX_ci mkMinj_correct l_distr eq1 eq2 split_beta nat_pow_mult)
      (simp add: a_ac m_ac)
qed

primrec mon_of_pol :: "pol \<Rightarrow> mon option"
where
  "mon_of_pol (Pc c) = Some (Mc c)"
| "mon_of_pol (Pinj i P) = (case mon_of_pol P of
       None \<Rightarrow> None
     | Some M \<Rightarrow> Some (mkMinj i M))"
| "mon_of_pol (PX P i Q) =
     (if Q = Pc 0 then (case mon_of_pol P of
          None \<Rightarrow> None
        | Some M \<Rightarrow> Some (mkMX i M))
      else None)"

lemma (in cring) mon_of_pol_correct:
  assumes "in_carrier l"
  and "mon_of_pol P = Some M"
  shows "Ipol l P = Imon l M"
  using assms
proof (induct P arbitrary: M l)
  case (PX P1 i P2)
  from PX(1,3,4)
  show ?case
    by (auto simp add: mkMinj_correct mkMX_correct split add: split_if_asm option.split_asm)
qed (auto simp add: mkMinj_correct split add: option.split_asm)

fun (in cring) Ipolex_polex_list :: "'a list \<Rightarrow> (polex \<times> polex) list \<Rightarrow> bool"
where
  "Ipolex_polex_list l [] = True"
| "Ipolex_polex_list l ((P, Q) # pps) = ((Ipolex l P = Ipolex l Q) \<and> Ipolex_polex_list l pps)"

fun (in cring) Imon_pol_list :: "'a list \<Rightarrow> (mon \<times> pol) list \<Rightarrow> bool"
where
  "Imon_pol_list l [] = True"
| "Imon_pol_list l ((M, P) # mps) = ((Imon l M = Ipol l P) \<and> Imon_pol_list l mps)"

fun mk_monpol_list :: "(polex \<times> polex) list \<Rightarrow> (mon \<times> pol) list"
where
  "mk_monpol_list [] = []"
| "mk_monpol_list ((P, Q) # pps) =
     (case mon_of_pol (norm P) of
        None \<Rightarrow> mk_monpol_list pps
      | Some M \<Rightarrow> (M, norm Q) # mk_monpol_list pps)"

lemma (in cring) mk_monpol_list_correct:
  "in_carrier l \<Longrightarrow> Ipolex_polex_list l pps \<Longrightarrow> Imon_pol_list l (mk_monpol_list pps)"
  by (induct pps rule: mk_monpol_list.induct)
    (auto split add: option.split
       simp add: norm_ci [symmetric] mon_of_pol_correct [symmetric])

definition ponesubst :: "pol \<Rightarrow> mon \<Rightarrow> pol \<Rightarrow> pol option" where
  "ponesubst P1 M P2 =
     (let (Q, R) = mfactor P1 M
      in case R of
          Pc c \<Rightarrow> if c = 0 then None else Some (add Q (mul P2 R))
        | _ \<Rightarrow> Some (add Q (mul P2 R)))"

fun pnsubst1 :: "pol \<Rightarrow> mon \<Rightarrow> pol \<Rightarrow> nat \<Rightarrow> pol"
where
  "pnsubst1 P1 M P2 n = (case ponesubst P1 M P2 of
       None \<Rightarrow> P1
     | Some P3 \<Rightarrow> if n = 0 then P3 else pnsubst1 P3 M P2 (n - 1))"

lemma pnsubst1_0 [simp]: "pnsubst1 P1 M P2 0 = (case ponesubst P1 M P2 of
  None \<Rightarrow> P1 | Some P3 \<Rightarrow> P3)"
  by (simp split add: option.split)

lemma pnsubst1_Suc [simp]: "pnsubst1 P1 M P2 (Suc n) = (case ponesubst P1 M P2 of
  None \<Rightarrow> P1 | Some P3 \<Rightarrow> pnsubst1 P3 M P2 n)"
  by (simp split add: option.split)

declare pnsubst1.simps [simp del]

definition pnsubst :: "pol \<Rightarrow> mon \<Rightarrow> pol \<Rightarrow> nat \<Rightarrow> pol option" where
  "pnsubst P1 M P2 n = (case ponesubst P1 M P2 of
       None \<Rightarrow> None
     | Some P3 \<Rightarrow> Some (pnsubst1 P3 M P2 n))"

fun psubstl1 :: "pol \<Rightarrow> (mon \<times> pol) list \<Rightarrow> nat \<Rightarrow> pol"
where
  "psubstl1 P1 [] n = P1"
| "psubstl1 P1 ((M, P2) # mps) n = psubstl1 (pnsubst1 P1 M P2 n) mps n"

fun psubstl :: "pol \<Rightarrow> (mon \<times> pol) list \<Rightarrow> nat \<Rightarrow> pol option"
where
  "psubstl P1 [] n = None"
| "psubstl P1 ((M, P2) # mps) n = (case pnsubst P1 M P2 n of
       None \<Rightarrow> psubstl P1 mps n
     | Some P3 \<Rightarrow> Some (psubstl1 P3 mps n))"

fun pnsubstl :: "pol \<Rightarrow> (mon \<times> pol) list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> pol"
where
  "pnsubstl P1 mps m n = (case psubstl P1 mps n of
       None \<Rightarrow> P1
     | Some P3 \<Rightarrow> if m = 0 then P3 else pnsubstl P3 mps (m - 1) n)"

lemma pnsubstl_0 [simp]: "pnsubstl P1 mps 0 n = (case psubstl P1 mps n of
  None \<Rightarrow> P1 | Some P3 \<Rightarrow> P3)"
  by (simp split add: option.split)

lemma pnsubstl_Suc [simp]: "pnsubstl P1 mps (Suc m) n = (case psubstl P1 mps n of
  None \<Rightarrow> P1 | Some P3 \<Rightarrow> pnsubstl P3 mps m n)"
  by (simp split add: option.split)

declare pnsubstl.simps [simp del]

lemma (in cring) ponesubst_correct:
  "in_carrier l \<Longrightarrow> ponesubst P1 M P2 = Some P3 \<Longrightarrow> Imon l M = Ipol l P2 \<Longrightarrow> Ipol l P1 = Ipol l P3"
  by (auto simp add: ponesubst_def split_beta mfactor_correct [of l P1 M]
    add_ci mul_ci split add: pol.split_asm split_if_asm)

lemma (in cring) pnsubst1_correct:
  "in_carrier l \<Longrightarrow> Imon l M = Ipol l P2 \<Longrightarrow> Ipol l (pnsubst1 P1 M P2 n) = Ipol l P1"
  by (induct n arbitrary: P1)
    (simp_all add: ponesubst_correct split add: option.split)

lemma (in cring) pnsubst_correct:
  "in_carrier l \<Longrightarrow> pnsubst P1 M P2 n = Some P3 \<Longrightarrow> Imon l M = Ipol l P2 \<Longrightarrow> Ipol l P1 = Ipol l P3"
  by (auto simp add: pnsubst_def
    pnsubst1_correct ponesubst_correct split add: option.split_asm)

lemma (in cring) psubstl1_correct:
  "in_carrier l \<Longrightarrow> Imon_pol_list l mps \<Longrightarrow> Ipol l (psubstl1 P1 mps n) = Ipol l P1"
  by (induct P1 mps n rule: psubstl1.induct) (simp_all add: pnsubst1_correct)

lemma (in cring) psubstl_correct:
  "in_carrier l \<Longrightarrow> psubstl P1 mps n = Some P2 \<Longrightarrow> Imon_pol_list l mps \<Longrightarrow> Ipol l P1 = Ipol l P2"
  by (induct P1 mps n rule: psubstl.induct)
    (auto simp add: psubstl1_correct pnsubst_correct split add: option.split_asm)

lemma (in cring) pnsubstl_correct:
  "in_carrier l \<Longrightarrow> Imon_pol_list l mps \<Longrightarrow> Ipol l (pnsubstl P1 mps m n) = Ipol l P1"
  by (induct m arbitrary: P1)
    (simp_all add: psubstl_correct split add: option.split)

lemma (in cring) norm_subst_correct:
  "in_carrier l \<Longrightarrow> Ipolex_polex_list l pps \<Longrightarrow>
   Ipolex l P = Ipol l (pnsubstl (norm P) (mk_monpol_list pps) m n)"
  by (simp add: pnsubstl_correct mk_monpol_list_correct norm_ci)

lemma in_carrier_trivial: "cring_class.in_carrier l"
  by (induct l) (simp_all add: cring_class.in_carrier_def carrier_class)

ML {*
signature RING_TAC =
sig
  structure Ring_Simps:
  sig
    type T
    val get: Context.generic -> T
    val put: T -> Context.generic -> Context.generic
    val map: (T -> T) -> Context.generic -> Context.generic
  end
  val insert_rules: ((term * 'a) * (term * 'a) -> bool) -> (term * 'a) ->
    (term * 'a) Net.net -> (term * 'a) Net.net
  val eq_ring_simps:
    (term * (thm list * thm list * thm list * thm list * thm * thm)) *
    (term * (thm list * thm list * thm list * thm list * thm * thm)) -> bool
  val ring_tac: bool -> thm list -> Proof.context -> int -> tactic
  val get_matching_rules: Proof.context -> (term * 'a) Net.net -> term -> 'a option
  val norm: thm -> thm
  val mk_in_carrier: Proof.context -> term -> thm list -> (string * typ) list -> thm
  val mk_ring: typ -> term
end

structure Ring_Tac : RING_TAC =
struct

fun eq_ring_simps
  ((t, (ths1, ths2, ths3, ths4, th5, th)),
   (t', (ths1', ths2', ths3', ths4', th5', th'))) =
    t aconv t' andalso
    eq_list Thm.eq_thm (ths1, ths1') andalso
    eq_list Thm.eq_thm (ths2, ths2') andalso
    eq_list Thm.eq_thm (ths3, ths3') andalso
    eq_list Thm.eq_thm (ths4, ths4') andalso
    Thm.eq_thm (th5, th5') andalso
    Thm.eq_thm (th, th');

structure Ring_Simps = Generic_Data
(struct
  type T = (term * (thm list * thm list * thm list * thm list * thm * thm)) Net.net
  val empty = Net.empty
  val extend = I
  val merge = Net.merge eq_ring_simps
end);

fun get_matching_rules ctxt net t = get_first
  (fn (p, x) =>
     if Pattern.matches (Proof_Context.theory_of ctxt) (p, t) then SOME x else NONE)
  (Net.match_term net t);

fun insert_rules eq (t, x) = Net.insert_term eq (t, (t, x));

fun norm thm = thm COMP_INCR asm_rl;

fun get_ring_simps ctxt optcT t =
  (case get_matching_rules ctxt (Ring_Simps.get (Context.Proof ctxt)) t of
     SOME (ths1, ths2, ths3, ths4, th5, th) =>
       let val tr =
         Thm.transfer (Proof_Context.theory_of ctxt) #>
         (case optcT of NONE => I | SOME cT => inst [cT] [] #> norm)
       in (map tr ths1, map tr ths2, map tr ths3, map tr ths4, tr th5, tr th) end
   | NONE => error "get_ring_simps: lookup failed");

fun ring_struct (Const (@{const_name Ring.ring.add}, _) $ R $ _ $ _) = SOME R
  | ring_struct (Const (@{const_name Ring.a_minus}, _) $ R $ _ $ _) = SOME R
  | ring_struct (Const (@{const_name Group.monoid.mult}, _) $ R $ _ $ _) = SOME R
  | ring_struct (Const (@{const_name Ring.a_inv}, _) $ R $ _) = SOME R
  | ring_struct (Const (@{const_name Group.pow}, _) $ R $ _ $ _) = SOME R
  | ring_struct (Const (@{const_name Ring.ring.zero}, _) $ R) = SOME R
  | ring_struct (Const (@{const_name Group.monoid.one}, _) $ R) = SOME R
  | ring_struct (Const (@{const_name Algebra_Aux.of_integer}, _) $ R $ _) = SOME R
  | ring_struct _ = NONE;

fun reif_polex vs (Const (@{const_name Ring.ring.add}, _) $ _ $ a $ b) =
      @{const Add} $ reif_polex vs a $ reif_polex vs b
  | reif_polex vs (Const (@{const_name Ring.a_minus}, _) $ _ $ a $ b) =
      @{const Sub} $ reif_polex vs a $ reif_polex vs b
  | reif_polex vs (Const (@{const_name Group.monoid.mult}, _) $ _ $ a $ b) =
      @{const Mul} $ reif_polex vs a $ reif_polex vs b
  | reif_polex vs (Const (@{const_name Ring.a_inv}, _) $ _ $ a) =
      @{const Neg} $ reif_polex vs a
  | reif_polex vs (Const (@{const_name Group.pow}, _) $ _ $ a $ n) =
      @{const Pow} $ reif_polex vs a $ n
  | reif_polex vs (Free x) =
      @{const Var} $ HOLogic.mk_number HOLogic.natT (find_index (equal x) vs)
  | reif_polex vs (Const (@{const_name Ring.ring.zero}, _) $ _) =
      @{term "Const 0"}
  | reif_polex vs (Const (@{const_name Group.monoid.one}, _) $ _) =
      @{term "Const 1"}
  | reif_polex vs (Const (@{const_name Algebra_Aux.of_integer}, _) $ _ $ n) =
      @{const Const} $ n
  | reif_polex _ _ = error "reif_polex: bad expression";

fun reif_polex' vs (Const (@{const_name Groups.plus}, _) $ a $ b) =
      @{const Add} $ reif_polex' vs a $ reif_polex' vs b
  | reif_polex' vs (Const (@{const_name Groups.minus}, _) $ a $ b) =
      @{const Sub} $ reif_polex' vs a $ reif_polex' vs b
  | reif_polex' vs (Const (@{const_name Groups.times}, _) $ a $ b) =
      @{const Mul} $ reif_polex' vs a $ reif_polex' vs b
  | reif_polex' vs (Const (@{const_name Groups.uminus}, _) $ a) =
      @{const Neg} $ reif_polex' vs a
  | reif_polex' vs (Const (@{const_name Power.power}, _) $ a $ n) =
      @{const Pow} $ reif_polex' vs a $ n
  | reif_polex' vs (Free x) =
      @{const Var} $ HOLogic.mk_number HOLogic.natT (find_index (equal x) vs)
  | reif_polex' vs (Const (@{const_name numeral}, _) $ b) =
      @{const Const} $ (@{const numeral (int)} $ b)
  | reif_polex' vs (Const (@{const_name zero_class.zero}, _)) = @{term "Const 0"}
  | reif_polex' vs (Const (@{const_name one_class.one}, _)) = @{term "Const 1"}
  | reif_polex' vs t = error "reif_polex: bad expression";

fun head_conv (_, _, _, _, head_simp, _) ys =
  (case strip_app ys of
     (@{const_name Cons}, [y, xs]) => inst [] [y, xs] head_simp);

fun Ipol_conv (rls as
      ([Ipol_simps_1, Ipol_simps_2, Ipol_simps_3,
        Ipol_simps_4, Ipol_simps_5, Ipol_simps_6,
        Ipol_simps_7], _, _, _, _, _)) =
  let
    val a = type_of_eqn Ipol_simps_1;
    val drop_conv_a = drop_conv a;

    fun conv l p = (case strip_app p of
        (@{const_name Pc}, [c]) => (case strip_numeral c of
            (@{const_name zero_class.zero}, _) => inst [] [l] Ipol_simps_4
          | (@{const_name one_class.one}, _) => inst [] [l] Ipol_simps_5
          | (@{const_name numeral}, [m]) => inst [] [l, m] Ipol_simps_6
          | (@{const_name uminus}, [m]) => inst [] [l, m] Ipol_simps_7
          | _ => inst [] [l, c] Ipol_simps_1)
      | (@{const_name Pinj}, [i, P]) =>
          transitive'
            (inst [] [l, i, P] Ipol_simps_2)
            (cong2' conv (args2 drop_conv_a) Thm.reflexive)
      | (@{const_name PX}, [P, x, Q]) =>
          transitive'
            (inst [] [l, P, x, Q] Ipol_simps_3)
            (cong2
               (cong2
                  (args2 conv) (cong2 (args1 (head_conv rls)) Thm.reflexive))
               (cong2' conv (args2 drop_conv_a) Thm.reflexive)))
  in conv end;

fun Ipolex_conv (rls as
      (_,
       [Ipolex_Var, Ipolex_Const, Ipolex_Add,
        Ipolex_Sub, Ipolex_Mul, Ipolex_Pow,
        Ipolex_Neg, Ipolex_Const_0, Ipolex_Const_1,
        Ipolex_Const_numeral], _, _, _, _)) =
  let
    val a = type_of_eqn Ipolex_Var;
    val drop_conv_a = drop_conv a;

    fun conv l r = (case strip_app r of
        (@{const_name Var}, [n]) =>
          transitive'
            (inst [] [l, n] Ipolex_Var)
            (cong1' (head_conv rls) (args2 drop_conv_a))
      | (@{const_name Const}, [i]) => (case strip_app i of
            (@{const_name zero_class.zero}, _) => inst [] [l] Ipolex_Const_0
          | (@{const_name one_class.one}, _) => inst [] [l] Ipolex_Const_1
          | (@{const_name numeral}, [m]) => inst [] [l, m] Ipolex_Const_numeral
          | _ => inst [] [l, i] Ipolex_Const)
      | (@{const_name Add}, [P, Q]) =>
          transitive'
            (inst [] [l, P, Q] Ipolex_Add)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name Sub}, [P, Q]) =>
          transitive'
            (inst [] [l, P, Q] Ipolex_Sub)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name Mul}, [P, Q]) =>
          transitive'
            (inst [] [l, P, Q] Ipolex_Mul)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name Pow}, [P, n]) =>
          transitive'
            (inst [] [l, P, n] Ipolex_Pow)
            (cong2 (args2 conv) Thm.reflexive)
      | (@{const_name Neg}, [P]) =>
          transitive'
            (inst [] [l, P] Ipolex_Neg)
            (cong1 (args2 conv)))
  in conv end;

fun Ipolex_polex_list_conv (rls as
      (_, _,
       [Ipolex_polex_list_Nil, Ipolex_polex_list_Cons], _, _, _)) l pps =
  (case strip_app pps of
     (@{const_name Nil}, []) => inst [] [l] Ipolex_polex_list_Nil
   | (@{const_name Cons}, [p, pps']) => (case strip_app p of
       (@{const_name Pair}, [P, Q]) =>
         transitive'
           (inst [] [l, P, Q, pps'] Ipolex_polex_list_Cons)
           (cong2
              (cong2 (args2 (Ipolex_conv rls)) (args2 (Ipolex_conv rls)))
              (args2 (Ipolex_polex_list_conv rls)))));

fun dest_conj th =
  let
    val th1 = th RS @{thm conjunct1};
    val th2 = th RS @{thm conjunct2}
  in
    dest_conj th1 @ dest_conj th2
  end handle THM _ => [th];

fun mk_in_carrier ctxt R prems xs =
  let
    val (_, _, _, [in_carrier_Nil, in_carrier_Cons], _, _) =
      get_ring_simps ctxt NONE R;
    val props = Facts.props (Proof_Context.facts_of ctxt) @ maps dest_conj prems;
    val ths = map (fn p as (x, _) =>
      (case find_first
         ((fn Const (@{const_name Trueprop}, _) $
                (Const (@{const_name Set.member}, _) $
                   Free (y, _) $ (Const (@{const_name carrier}, _) $ S)) =>
                x = y andalso R aconv S
            | _ => false) o Thm.prop_of) props of
         SOME th => th
       | NONE => error ("Variable " ^ Syntax.string_of_term ctxt (Free p) ^
           " not in carrier"))) xs
  in
    fold_rev (fn th1 => fn th2 => [th1, th2] MRS in_carrier_Cons)
       ths in_carrier_Nil
  end;

fun mk_ring T =
  Const (@{const_name cring_class_ops},
    Type (@{type_name partial_object_ext}, [T,
      Type (@{type_name monoid_ext}, [T,
        Type (@{type_name ring_ext}, [T, @{typ unit}])])]));

val iterations = @{cterm "1000::nat"};
val Trueprop_cong = Thm.combination (Thm.reflexive @{cterm Trueprop});

fun commutative_ring_conv ctxt prems eqs ct =
  let
    val cT = Thm.ctyp_of_cterm ct;
    val T = Thm.typ_of cT;
    val eqs' = map (HOLogic.dest_eq o HOLogic.dest_Trueprop o Thm.prop_of) eqs;
    val xs = filter (equal T o snd) (rev (fold Term.add_frees
      (map fst eqs' @ map snd eqs' @ [Thm.term_of ct]) []));
    val (R, optcT, prem', reif) = (case ring_struct (Thm.term_of ct) of
        SOME R => (R, NONE, mk_in_carrier ctxt R prems xs, reif_polex xs)
      | NONE => (mk_ring T, SOME cT, @{thm in_carrier_trivial}, reif_polex' xs));
    val rls as (_, _, _, _, _, norm_subst_correct) = get_ring_simps ctxt optcT R;
    val cxs = Thm.cterm_of ctxt (HOLogic.mk_list T (map Free xs));
    val ceqs = Thm.cterm_of ctxt (HOLogic.mk_list @{typ "polex * polex"}
      (map (HOLogic.mk_prod o apply2 reif) eqs'));
    val cp = Thm.cterm_of ctxt (reif (Thm.term_of ct));
    val prem = Thm.equal_elim
      (Trueprop_cong (Thm.symmetric (Ipolex_polex_list_conv rls cxs ceqs)))
      (fold_rev (fn th1 => fn th2 => [th1, th2] MRS @{thm conjI})
         eqs @{thm TrueI});
  in
    Thm.transitive
      (Thm.symmetric (Ipolex_conv rls cxs cp))
      (transitive'
         ([prem', prem] MRS inst [] [cxs, ceqs, cp, iterations, iterations]
            norm_subst_correct)
         (cong2' (Ipol_conv rls)
            Thm.reflexive
            (Code_Evaluation.dynamic_conv ctxt)))
  end;  

fun ring_tac in_prems thms ctxt =
  tactic_of_conv (fn ct =>
    (if in_prems then Conv.prems_conv else Conv.concl_conv)
      (Logic.count_prems (Thm.term_of ct))
      (Conv.arg_conv (Conv.binop_conv (commutative_ring_conv ctxt [] thms))) ct) THEN'
  TRY o (assume_tac ctxt ORELSE' resolve_tac ctxt [@{thm refl}]);

end
*}

context cring begin

local_setup {*
Local_Theory.declaration {syntax = false, pervasive = false}
  (fn phi => Ring_Tac.Ring_Simps.map (Ring_Tac.insert_rules Ring_Tac.eq_ring_simps
    (Morphism.term phi @{term R},
     (Morphism.fact phi @{thms Ipol.simps [meta] Ipol_Pc [meta]},
      Morphism.fact phi @{thms Ipolex.simps [meta] Ipolex_Const [meta]},
      Morphism.fact phi @{thms Ipolex_polex_list.simps [meta]},
      Morphism.fact phi @{thms in_carrier_Nil in_carrier_Cons},
      singleton (Morphism.fact phi) @{thm head.simps(2) [meta]},
      singleton (Morphism.fact phi) @{thm norm_subst_correct [meta]}))))
*}

end

method_setup ring = {*
  Scan.lift (Args.mode "prems") -- Attrib.thms >> (SIMPLE_METHOD' oo uncurry Ring_Tac.ring_tac)
*} "simplify equations involving rings"

end
