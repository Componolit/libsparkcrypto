theory Elliptic
imports Reflective_Field
begin

datatype 'a point = Infinity | Point 'a 'a

locale ell_field = field +
  assumes two_not_zero: "\<guillemotleft>2\<guillemotright> \<noteq> \<zero>"
begin

declare two_not_zero [simplified, simp add]

lemma neg_equal_zero:
  assumes x: "x \<in> carrier R"
  shows "(\<ominus> x = x) = (x = \<zero>)"
proof
  assume "\<ominus> x = x"
  with x have "\<guillemotleft>2\<guillemotright> \<otimes> x = x \<oplus> \<ominus> x"
    by (simp add: of_int_2 l_distr)
  with x show "x = \<zero>" by (simp add: r_neg integral_iff)
qed simp

lemmas equal_neg_zero = trans [OF eq_commute neg_equal_zero]

definition nonsingular :: "'a \<Rightarrow> 'a \<Rightarrow> bool" where
  "nonsingular a b = (\<guillemotleft>4\<guillemotright> \<otimes> a (^) (3::nat) \<oplus> \<guillemotleft>27\<guillemotright> \<otimes> b (^) (2::nat) \<noteq> \<zero>)"

definition on_curve :: "'a \<Rightarrow> 'a \<Rightarrow> 'a point \<Rightarrow> bool" where
  "on_curve a b p = (case p of
       Infinity \<Rightarrow> True
     | Point x y \<Rightarrow> x \<in> carrier R \<and> y \<in> carrier R \<and>
         y (^) (2::nat) = x (^) (3::nat) \<oplus> a \<otimes> x \<oplus> b)"

definition add :: "'a \<Rightarrow> 'a point \<Rightarrow> 'a point \<Rightarrow> 'a point" where
  "add a p\<^sub>1 p\<^sub>2 = (case p\<^sub>1 of
       Infinity \<Rightarrow> p\<^sub>2
     | Point x\<^sub>1 y\<^sub>1 \<Rightarrow> (case p\<^sub>2 of
         Infinity \<Rightarrow> p\<^sub>1
       | Point x\<^sub>2 y\<^sub>2 \<Rightarrow>
           if x\<^sub>1 = x\<^sub>2 then
             if y\<^sub>1 = \<ominus> y\<^sub>2 then Infinity
             else
               let
                 l = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>1);
                 x\<^sub>3 = l (^) (2::nat) \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>1
               in
                 Point x\<^sub>3 (\<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1))
           else
             let
               l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1);
               x\<^sub>3 = l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2
             in
               Point x\<^sub>3 (\<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1))))"

definition opp :: "'a point \<Rightarrow> 'a point" where
  "opp p = (case p of
       Infinity \<Rightarrow> Infinity
     | Point x y \<Rightarrow> Point x (\<ominus> y))"

lemma on_curve_infinity [simp]: "on_curve a b Infinity"
  by (simp add: on_curve_def)

lemma opp_Infinity [simp]: "opp Infinity = Infinity"
  by (simp add: opp_def)

lemma opp_Point: "opp (Point x y) = Point x (\<ominus> y)"
  by (simp add: opp_def)

lemma opp_opp: "on_curve a b p \<Longrightarrow> opp (opp p) = p"
  by (auto simp add: opp_def on_curve_def split: point.split)

lemma opp_closed:
  "on_curve a b p \<Longrightarrow> on_curve a b (opp p)"
  by (auto simp add: on_curve_def opp_def power2_eq_square
    l_minus r_minus split add: point.split)

lemma curve_elt_opp:
  assumes "p\<^sub>1 = Point x\<^sub>1 y\<^sub>1"
  and "p\<^sub>2 = Point x\<^sub>2 y\<^sub>2"
  and "on_curve a b p\<^sub>1"
  and "on_curve a b p\<^sub>2"
  and "x\<^sub>1 = x\<^sub>2"
  shows "p\<^sub>1 = p\<^sub>2 \<or> p\<^sub>1 = opp p\<^sub>2"
proof -
  from `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `on_curve a b p\<^sub>1`
  have "y\<^sub>1 \<in> carrier R" "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
    by (simp_all add: on_curve_def)
  moreover from `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `on_curve a b p\<^sub>2` `x\<^sub>1 = x\<^sub>2`
  have "y\<^sub>2 \<in> carrier R" "x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b = y\<^sub>2 (^) (2::nat)"
    by (simp_all add: on_curve_def)
  ultimately have "y\<^sub>1 = y\<^sub>2 \<or> y\<^sub>1 = \<ominus> y\<^sub>2"
    by (simp add: square_eq_iff power2_eq_square)
  with `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `x\<^sub>1 = x\<^sub>2`show ?thesis
    by (auto simp add: opp_def)
qed

lemma add_closed:
  assumes "a \<in> carrier R" and "b \<in> carrier R"
  and "on_curve a b p\<^sub>1" and "on_curve a b p\<^sub>2"
  shows "on_curve a b (add a p\<^sub>1 p\<^sub>2)"
proof (cases p\<^sub>1)
  case (Point x\<^sub>1 y\<^sub>1)
  note Point' = this
  show ?thesis
  proof (cases p\<^sub>2)
    case (Point x\<^sub>2 y\<^sub>2)
    show ?thesis
    proof (cases "x\<^sub>1 = x\<^sub>2")
      case True
      note True' = this
      show ?thesis
      proof (cases "y\<^sub>1 = \<ominus> y\<^sub>2")
        case True
        with True' Point Point'
        show ?thesis
          by (simp add: on_curve_def add_def)
      next
        case False
        from `on_curve a b p\<^sub>1` Point' True'
        have "x\<^sub>2 \<in> carrier R" "y\<^sub>1 \<in> carrier R" and
          on_curve1: "y\<^sub>1 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
          by (simp_all add: on_curve_def)
        from False True' Point Point' assms
        have "y\<^sub>1 \<noteq> \<zero>"
          apply (auto simp add: on_curve_def nat_pow_zero)
          apply (drule sym [of \<zero>])
          apply simp
          done
        with False True' Point Point' assms
        show ?thesis
          apply (simp add: on_curve_def add_def Let_def integral_iff)
          apply (field on_curve1)
          apply (simp add: integral_iff)
          done
      qed
    next
      case False
      from `on_curve a b p\<^sub>1` Point'
      have  "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
        and on_curve1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
        by (simp_all add: on_curve_def)
      from `on_curve a b p\<^sub>2` Point
      have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
        and on_curve2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
        by (simp_all add: on_curve_def)
      from assms not_sym [OF False] show ?thesis
        apply (simp add: on_curve_def add_def Let_def False Point Point' eq_diff0)
        apply (field on_curve1 on_curve2)
        apply (simp add: eq_diff0)
        done
    qed
  next
    case Infinity
    with Point `on_curve a b p\<^sub>1` show ?thesis
      by (simp add: add_def)
  qed
next
  case Infinity
  with `on_curve a b p\<^sub>2` show ?thesis
    by (simp add: add_def)
qed

lemma add_case [consumes 4, case_names InfL InfR Opp Tan Gen]:
  assumes "a \<in> carrier R"
  and "b \<in> carrier R"
  and p: "on_curve a b p"
  and q: "on_curve a b q"
  and R1: "\<And>p. P Infinity p p"
  and R2: "\<And>p. P p Infinity p"
  and R3: "\<And>p. on_curve a b p \<Longrightarrow> P p (opp p) Infinity"
  and R4: "\<And>p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l.
    p\<^sub>1 = Point x\<^sub>1 y\<^sub>1 \<Longrightarrow> p\<^sub>2 = Point x\<^sub>2 y\<^sub>2 \<Longrightarrow>
(*    on_curve a b p\<^sub>1 \<Longrightarrow> on_curve a b p\<^sub>2 \<Longrightarrow> *)
    p\<^sub>2 = add a p\<^sub>1 p\<^sub>1 \<Longrightarrow> y\<^sub>1 \<noteq> \<zero> \<Longrightarrow>
    l = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>1) \<Longrightarrow>
    x\<^sub>2 = l (^) (2::nat) \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>1 \<Longrightarrow>
    y\<^sub>2 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>2 \<ominus> x\<^sub>1) \<Longrightarrow>
    P p\<^sub>1 p\<^sub>1 p\<^sub>2"
  and R5: "\<And>p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l.
    p\<^sub>1 = Point x\<^sub>1 y\<^sub>1 \<Longrightarrow> p\<^sub>2 = Point x\<^sub>2 y\<^sub>2 \<Longrightarrow> p\<^sub>3 = Point x\<^sub>3 y\<^sub>3 \<Longrightarrow>
(*    on_curve a b p\<^sub>1 \<Longrightarrow> on_curve a b p\<^sub>2 \<Longrightarrow> on_curve a b p\<^sub>3 \<Longrightarrow> *)
    p\<^sub>3 = add a p\<^sub>1 p\<^sub>2 \<Longrightarrow> x\<^sub>1 \<noteq> x\<^sub>2 \<Longrightarrow>
    l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1) \<Longrightarrow>
    x\<^sub>3 = l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2 \<Longrightarrow>
    y\<^sub>3 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1) \<Longrightarrow>
    P p\<^sub>1 p\<^sub>2 p\<^sub>3"
  shows "P p q (add a p q)"
proof (cases p)
  case Infinity
  then show ?thesis
    by (simp add: add_def R1)
next
  case (Point x\<^sub>1 y\<^sub>1)
  note Point' = this
  with p have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
    and p': "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
    by (simp_all add: on_curve_def)
  show ?thesis
  proof (cases q)
    case Infinity
    with Point show ?thesis
      by (simp add: add_def R2)
  next
    case (Point x\<^sub>2 y\<^sub>2)
    with q have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
      and q': "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
      by (simp_all add: on_curve_def)
    show ?thesis
    proof (cases "x\<^sub>1 = x\<^sub>2")
      case True
      note True' = this
      show ?thesis
      proof (cases "y\<^sub>1 = \<ominus> y\<^sub>2")
        case True
        with p Point Point' True' R3 [of p] `y\<^sub>2 \<in> carrier R` show ?thesis
          by (simp add: add_def opp_def)
      next
        case False
        have "(y\<^sub>1 \<ominus> y\<^sub>2) \<otimes> (y\<^sub>1 \<oplus> y\<^sub>2) = \<zero>"
          by (ring True' p' q')
        with False `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R` have "y\<^sub>1 = y\<^sub>2"
          by (simp add: eq_neg_iff_add_eq_0 integral_iff eq_diff0)
        with False True' Point Point' show ?thesis
          apply simp
          apply (rule R4)
          apply (auto simp add: add_def Let_def)
          done
      qed
    next
      case False
      with Point Point' show ?thesis
        apply -
        apply (rule R5)
        apply (auto simp add: add_def Let_def)
        done
    qed
  qed
qed

lemma add_casew [consumes 4, case_names InfL InfR Opp Gen]:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p: "on_curve a b p"
  and q: "on_curve a b q"
  and R1: "\<And>p. P Infinity p p"
  and R2: "\<And>p. P p Infinity p"
  and R3: "\<And>p. on_curve a b p \<Longrightarrow> P p (opp p) Infinity"
  and R4: "\<And>p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l.
    p\<^sub>1 = Point x\<^sub>1 y\<^sub>1 \<Longrightarrow> p\<^sub>2 = Point x\<^sub>2 y\<^sub>2 \<Longrightarrow> p\<^sub>3 = Point x\<^sub>3 y\<^sub>3 \<Longrightarrow>
    p\<^sub>3 = add a p\<^sub>1 p\<^sub>2 \<Longrightarrow> p\<^sub>1 \<noteq> opp p\<^sub>2 \<Longrightarrow>
    x\<^sub>1 = x\<^sub>2 \<and> y\<^sub>1 = y\<^sub>2 \<and> l = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>1) \<or>
    x\<^sub>1 \<noteq> x\<^sub>2 \<and> l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1) \<Longrightarrow>
    x\<^sub>3 = l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2 \<Longrightarrow>
    y\<^sub>3 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1) \<Longrightarrow>
    P p\<^sub>1 p\<^sub>2 p\<^sub>3"
  shows "P p q (add a p q)"
  using a b p q p q
proof (induct rule: add_case)
  case InfL
  show ?case by (rule R1)
next
  case InfR
  show ?case by (rule R2)
next
  case (Opp p)
  from `on_curve a b p` show ?case by (rule R3)
next
  case (Tan p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l)
  with a b show ?case
    apply (rule_tac R4)
    apply assumption+
    apply (simp add: opp_Point equal_neg_zero on_curve_def)
    apply simp
    apply (simp add: minus_eq mult2 integral_iff a_assoc r_minus on_curve_def)
    apply simp
    done
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
  then show ?case
    apply (rule_tac R4)
    apply assumption+
    apply (simp add: opp_Point)
    apply simp_all
    done
qed

definition
  "is_tangent p q = (p \<noteq> Infinity \<and> p = q \<and> p \<noteq> opp q)"

definition
  "is_generic p q =
     (p \<noteq> Infinity \<and> q \<noteq> Infinity \<and>
      p \<noteq> q \<and> p \<noteq> opp q)"

definition
  "is_gotan p q = (p \<noteq> Infinity \<and> q \<noteq> Infinity \<and> p \<noteq> opp q)"

lemma spec1_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and "is_generic p\<^sub>1 p\<^sub>2"
  and "is_generic p\<^sub>2 p\<^sub>3"
  and "is_generic (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  and "is_generic p\<^sub>1 (add a p\<^sub>2 p\<^sub>3)"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  using a b p\<^sub>1 p\<^sub>2 assms
proof (induct rule: add_case)
  case InfL
  show ?case by (simp add: add_def)
next
  case InfR
  show ?case by (simp add: add_def)
next
  case Opp
  then show ?case by (simp add: is_generic_def)
next
  case Tan
  then show ?case by (simp add: is_generic_def)
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>4 x\<^sub>4 y\<^sub>4 l)
  with a b `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>3`
  show ?case
  proof (induct rule: add_case)
    case InfL
    then show ?case by (simp add: is_generic_def)
  next
    case InfR
    then show ?case by (simp add: is_generic_def)
  next
    case Opp
    then show ?case by (simp add: is_generic_def)
  next
    case Tan
    then show ?case by (simp add: is_generic_def)
  next
    case (Gen p\<^sub>2 x\<^sub>2' y\<^sub>2' p\<^sub>3 x\<^sub>3 y\<^sub>3 p\<^sub>5 x\<^sub>5 y\<^sub>5 l\<^sub>1)
    from a b `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>3` `p\<^sub>5 = add a p\<^sub>2 p\<^sub>3`
    have "on_curve a b p\<^sub>5" by (simp add: add_closed)
    with a b `on_curve a b p\<^sub>1` show ?case using Gen [simplified `p\<^sub>2 = Point x\<^sub>2' y\<^sub>2'`]
    proof (induct rule: add_case)
      case InfL
      then show ?case by (simp add: is_generic_def)
    next
      case InfR
      then show ?case by (simp add: is_generic_def)
    next
      case (Opp p)
      from `on_curve a b p` `is_generic p (opp p)`
      show ?case by (simp add: is_generic_def opp_opp)
    next
      case Tan
      then show ?case by (simp add: is_generic_def)
    next
(*      case (Gen p x\<^sub>1' y\<^sub>1' p\<^sub>5' x\<^sub>5' y\<^sub>5' p\<^sub>2 x\<^sub>6 y\<^sub>6 l\<^sub>2) *)
      case (Gen p\<^sub>1 x\<^sub>1' y\<^sub>1' p\<^sub>5' x\<^sub>5' y\<^sub>5' p\<^sub>6 x\<^sub>6 y\<^sub>6 l\<^sub>2)
      from a b `on_curve a b p\<^sub>1` `on_curve a b (Point x\<^sub>2' y\<^sub>2')`
        `p\<^sub>4 = add a p\<^sub>1 (Point x\<^sub>2' y\<^sub>2')`
      have "on_curve a b p\<^sub>4" by (simp add: add_closed)
      with a b show ?case using `on_curve a b p\<^sub>3` Gen
      proof (induct rule: add_case)
        case InfL
        then show ?case by (simp add: is_generic_def)
      next
        case InfR
        then show ?case by (simp add: is_generic_def)
      next
        case (Opp p)
        from `on_curve a b p` `is_generic p (opp p)`
        show ?case by (simp add: is_generic_def opp_opp)
      next
        case Tan
        then show ?case by (simp add: is_generic_def)
      next
        case (Gen p\<^sub>4' x\<^sub>4' y\<^sub>4' p\<^sub>3' x\<^sub>3' y\<^sub>3' p\<^sub>7 x\<^sub>7 y\<^sub>7 l\<^sub>3)
        from `p\<^sub>4' = Point x\<^sub>4' y\<^sub>4'` `p\<^sub>4' = Point x\<^sub>4 y\<^sub>4`
        have p\<^sub>4: "x\<^sub>4' = x\<^sub>4" "y\<^sub>4' = y\<^sub>4" by simp_all
        from `p\<^sub>3' = Point x\<^sub>3' y\<^sub>3'` `p\<^sub>3' = Point x\<^sub>3 y\<^sub>3`
        have p\<^sub>3: "x\<^sub>3' = x\<^sub>3" "y\<^sub>3' = y\<^sub>3" by simp_all
        from `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
        have p\<^sub>1: "x\<^sub>1' = x\<^sub>1" "y\<^sub>1' = y\<^sub>1" by simp_all
        from `p\<^sub>5' = Point x\<^sub>5' y\<^sub>5'` `p\<^sub>5' = Point x\<^sub>5 y\<^sub>5`
        have p\<^sub>5: "x\<^sub>5' = x\<^sub>5" "y\<^sub>5' = y\<^sub>5" by simp_all
        from `Point x\<^sub>2' y\<^sub>2' = Point x\<^sub>2 y\<^sub>2`
        have p\<^sub>2: "x\<^sub>2' = x\<^sub>2" "y\<^sub>2' = y\<^sub>2" by simp_all
        note ps = p\<^sub>1 p\<^sub>2 p\<^sub>3 p\<^sub>4 p\<^sub>5
        from
          `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
          `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
          `on_curve a b p\<^sub>3` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
        have
          "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" and y1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b" and
          "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R" and y2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b" and
          "x\<^sub>3 \<in> carrier R" "y\<^sub>3 \<in> carrier R" and y3: "y\<^sub>3 (^) (2::nat) = x\<^sub>3 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>3 \<oplus> b"
          by (simp_all add: on_curve_def)
        show ?case
          apply (simp add: `p\<^sub>6 = Point x\<^sub>6 y\<^sub>6` `p\<^sub>7 = Point x\<^sub>7 y\<^sub>7`)
          apply (simp only: ps
            `x\<^sub>6 = l\<^sub>2 (^) 2 \<ominus> x\<^sub>1' \<ominus> x\<^sub>5'` `x\<^sub>7 = l\<^sub>3 (^) 2 \<ominus> x\<^sub>4' \<ominus> x\<^sub>3'`
            `y\<^sub>6 = \<ominus> y\<^sub>1' \<ominus> l\<^sub>2 \<otimes> (x\<^sub>6 \<ominus> x\<^sub>1')` `y\<^sub>7 = \<ominus> y\<^sub>4' \<ominus> l\<^sub>3 \<otimes> (x\<^sub>7 \<ominus> x\<^sub>4')`
            `l\<^sub>2 = (y\<^sub>5' \<ominus> y\<^sub>1') \<oslash> (x\<^sub>5' \<ominus> x\<^sub>1')` `l\<^sub>3 = (y\<^sub>3' \<ominus> y\<^sub>4') \<oslash> (x\<^sub>3' \<ominus> x\<^sub>4')`
            `l\<^sub>1 = (y\<^sub>3 \<ominus> y\<^sub>2') \<oslash> (x\<^sub>3 \<ominus> x\<^sub>2')` `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`
            `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> x\<^sub>2' \<ominus> x\<^sub>3` `y\<^sub>5 = \<ominus> y\<^sub>2' \<ominus> l\<^sub>1 \<otimes> (x\<^sub>5 \<ominus> x\<^sub>2')`
            `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2` `y\<^sub>4 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1)`)
          apply (rule conjI)
          apply (field y1 y2 y3)
          apply (rule conjI)
          apply (simp add: eq_diff0 `x\<^sub>3 \<in> carrier R` `x\<^sub>2 \<in> carrier R`
            not_sym [OF `x\<^sub>2' \<noteq> x\<^sub>3` [simplified `x\<^sub>2' = x\<^sub>2`]])
          apply (rule conjI)
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (cut_tac `x\<^sub>1' \<noteq> x\<^sub>5'` [simplified `x\<^sub>5' = x\<^sub>5` `x\<^sub>1' = x\<^sub>1` `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> x\<^sub>2' \<ominus> x\<^sub>3`
            `l\<^sub>1 = (y\<^sub>3 \<ominus> y\<^sub>2') \<oslash> (x\<^sub>3 \<ominus> x\<^sub>2')` `y\<^sub>2' = y\<^sub>2` `x\<^sub>2' = x\<^sub>2`])
          apply (erule notE)
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: eq_diff0 `x\<^sub>3 \<in> carrier R` `x\<^sub>2 \<in> carrier R`
            not_sym [OF `x\<^sub>2' \<noteq> x\<^sub>3` [simplified `x\<^sub>2' = x\<^sub>2`]])
          apply (rule conjI)
          apply (simp add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (cut_tac `x\<^sub>4' \<noteq> x\<^sub>3'` [simplified `x\<^sub>4' = x\<^sub>4` `x\<^sub>3' = x\<^sub>3` `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
            `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`])
          apply (erule notE)
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (field y1 y2 y3)
          apply (rule conjI)
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (cut_tac `x\<^sub>1' \<noteq> x\<^sub>5'` [simplified `x\<^sub>5' = x\<^sub>5` `x\<^sub>1' = x\<^sub>1` `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> x\<^sub>2' \<ominus> x\<^sub>3`
            `l\<^sub>1 = (y\<^sub>3 \<ominus> y\<^sub>2') \<oslash> (x\<^sub>3 \<ominus> x\<^sub>2')` `y\<^sub>2' = y\<^sub>2` `x\<^sub>2' = x\<^sub>2`])
          apply (erule notE)
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: eq_diff0 `x\<^sub>3 \<in> carrier R` `x\<^sub>2 \<in> carrier R`
            not_sym [OF `x\<^sub>2' \<noteq> x\<^sub>3` [simplified `x\<^sub>2' = x\<^sub>2`]])
          apply (rule conjI)
          apply (simp add: eq_diff0 `x\<^sub>3 \<in> carrier R` `x\<^sub>2 \<in> carrier R`
            not_sym [OF `x\<^sub>2' \<noteq> x\<^sub>3` [simplified `x\<^sub>2' = x\<^sub>2`]])
          apply (rule conjI)
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (cut_tac `x\<^sub>4' \<noteq> x\<^sub>3'` [simplified `x\<^sub>4' = x\<^sub>4` `x\<^sub>3' = x\<^sub>3` `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
            `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`])
          apply (erule notE)
          apply (rule sym)
          apply (field y1 y2)
          apply (simp_all add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          done
      qed
    qed
  qed
qed

lemma spec2_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and "is_generic p\<^sub>1 p\<^sub>2"
  and "is_tangent p\<^sub>2 p\<^sub>3"
  and "is_generic (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  and "is_generic p\<^sub>1 (add a p\<^sub>2 p\<^sub>3)"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  using a b p\<^sub>1 p\<^sub>2 assms
proof (induct rule: add_case)
  case InfL
  show ?case by (simp add: add_def)
next
  case InfR
  show ?case by (simp add: add_def)
next
  case Opp
  then show ?case by (simp add: is_generic_def)
next
  case Tan
  then show ?case by (simp add: is_generic_def)
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>4 x\<^sub>4 y\<^sub>4 l)
  with a b `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>3`
  show ?case
  proof (induct rule: add_case)
    case InfL
    then show ?case by (simp add: is_generic_def)
  next
    case InfR
    then show ?case by (simp add: is_generic_def)
  next
    case Opp
    then show ?case by (simp add: is_generic_def)
  next
    case (Tan p\<^sub>2 x\<^sub>2' y\<^sub>2' p\<^sub>5 x\<^sub>5 y\<^sub>5 l\<^sub>1)
    from a b `on_curve a b p\<^sub>2` `p\<^sub>5 = add a p\<^sub>2 p\<^sub>2`
    have "on_curve a b p\<^sub>5" by (simp add: add_closed)
    with a b `on_curve a b p\<^sub>1` show ?case using Tan
    proof (induct rule: add_case)
      case InfL
      then show ?case by (simp add: is_generic_def)
    next
      case InfR
      then show ?case by (simp add: is_generic_def)
    next
      case (Opp p)
      from `is_generic p (opp p)` `on_curve a b p`
      show ?case by (simp add: is_generic_def opp_opp)
    next
      case Tan
      then show ?case by (simp add: is_generic_def)
    next
      case (Gen p\<^sub>1 x\<^sub>1' y\<^sub>1' p\<^sub>5' x\<^sub>5' y\<^sub>5' p\<^sub>6 x\<^sub>6 y\<^sub>6 l\<^sub>2)
      from a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2`
      have "on_curve a b p\<^sub>4" by (simp add: add_closed)
      with a b show ?case using `on_curve a b p\<^sub>2` Gen
      proof (induct rule: add_case)
        case InfL
        then show ?case by (simp add: is_generic_def)
      next
        case InfR
        then show ?case by (simp add: is_generic_def)
      next
        case (Opp p)
        from `is_generic p (opp p)` `on_curve a b p`
        show ?case by (simp add: is_generic_def opp_opp)
      next
        case Tan
        then show ?case by (simp add: is_generic_def)
      next
        case (Gen p\<^sub>4' x\<^sub>4' y\<^sub>4' p\<^sub>3' x\<^sub>3' y\<^sub>3' p\<^sub>7 x\<^sub>7 y\<^sub>7 l\<^sub>3)
        from
          `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
          `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
        have
          "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" and y1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b" and
          "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R" and y2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
          by (simp_all add: on_curve_def)
        from
          `p\<^sub>5' = Point x\<^sub>5' y\<^sub>5'`
          `p\<^sub>5' = Point x\<^sub>5 y\<^sub>5`
          `p\<^sub>4' = Point x\<^sub>4' y\<^sub>4'`
          `p\<^sub>4' = Point x\<^sub>4 y\<^sub>4`
          `p\<^sub>3' = Point x\<^sub>2' y\<^sub>2'`
          `p\<^sub>3' = Point x\<^sub>2 y\<^sub>2`
          `p\<^sub>3' = Point x\<^sub>3' y\<^sub>3'`
          `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'`
          `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
        have ps:
          "x\<^sub>5' = x\<^sub>5" "y\<^sub>5' = y\<^sub>5"
          "x\<^sub>4' = x\<^sub>4" "y\<^sub>4' = y\<^sub>4" "x\<^sub>3' = x\<^sub>2" "y\<^sub>3' = y\<^sub>2" "x\<^sub>2' = x\<^sub>2" "y\<^sub>2' = y\<^sub>2"
          "x\<^sub>1' = x\<^sub>1" "y\<^sub>1' = y\<^sub>1"
          by simp_all
        show ?case
          apply (simp add: `p\<^sub>6 = Point x\<^sub>6 y\<^sub>6` `p\<^sub>7 = Point x\<^sub>7 y\<^sub>7`)
          apply (simp only: ps
            `x\<^sub>7 = l\<^sub>3 (^) 2 \<ominus> x\<^sub>4' \<ominus> x\<^sub>3'`
            `y\<^sub>7 = \<ominus> y\<^sub>4' \<ominus> l\<^sub>3 \<otimes> (x\<^sub>7 \<ominus> x\<^sub>4')`
            `l\<^sub>3 = (y\<^sub>3' \<ominus> y\<^sub>4') \<oslash> (x\<^sub>3' \<ominus> x\<^sub>4')`
            `x\<^sub>6 = l\<^sub>2 (^) 2 \<ominus> x\<^sub>1' \<ominus> x\<^sub>5'`
            `y\<^sub>6 = \<ominus> y\<^sub>1' \<ominus> l\<^sub>2 \<otimes> (x\<^sub>6 \<ominus> x\<^sub>1')`
            `l\<^sub>2 = (y\<^sub>5' \<ominus> y\<^sub>1') \<oslash> (x\<^sub>5' \<ominus> x\<^sub>1')`
            `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2'`
            `y\<^sub>5 = \<ominus> y\<^sub>2' \<ominus> l\<^sub>1 \<otimes> (x\<^sub>5 \<ominus> x\<^sub>2')`
            `l\<^sub>1 = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2' (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2')`
            `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
            `y\<^sub>4 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1)`
            `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`)
          apply (rule conjI)
          apply (field y1 y2)
          apply (intro conjI)
          apply (simp add: integral_iff [OF _ `y\<^sub>2 \<in> carrier R`] `y\<^sub>2' \<noteq> \<zero>` [simplified `y\<^sub>2' = y\<^sub>2`])
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (rule notE [OF `x\<^sub>1' \<noteq> x\<^sub>5'` [simplified
            `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2'`
            `l\<^sub>1 = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2' (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2')`
            `x\<^sub>1' = x\<^sub>1` `x\<^sub>2' = x\<^sub>2` `y\<^sub>2' = y\<^sub>2` `x\<^sub>5' = x\<^sub>5`]])
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: integral_iff [OF _ `y\<^sub>2 \<in> carrier R`] `y\<^sub>2' \<noteq> \<zero>` [simplified `y\<^sub>2' = y\<^sub>2`])
          apply (simp add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (rule notE [OF `x\<^sub>4' \<noteq> x\<^sub>3'` [simplified
            `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
            `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`
            `x\<^sub>4' = x\<^sub>4` `x\<^sub>3' = x\<^sub>2`]])
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (field y1 y2)
          apply (intro conjI)
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (rule notE [OF `x\<^sub>1' \<noteq> x\<^sub>5'` [simplified
            `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2'`
            `l\<^sub>1 = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2' (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2')`
            `x\<^sub>1' = x\<^sub>1` `x\<^sub>2' = x\<^sub>2` `y\<^sub>2' = y\<^sub>2` `x\<^sub>5' = x\<^sub>5`]])
          apply (rule sym)
          apply (field y1 y2)
          apply (simp add: integral_iff [OF _ `y\<^sub>2 \<in> carrier R`] `y\<^sub>2' \<noteq> \<zero>` [simplified `y\<^sub>2' = y\<^sub>2`])
          apply (simp add: integral_iff [OF _ `y\<^sub>2 \<in> carrier R`] `y\<^sub>2' \<noteq> \<zero>` [simplified `y\<^sub>2' = y\<^sub>2`])
          apply (rule notI)
          apply (ring (prems) y1 y2)
          apply (rule notE [OF `x\<^sub>4' \<noteq> x\<^sub>3'` [simplified
            `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
            `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`
            `x\<^sub>4' = x\<^sub>4` `x\<^sub>3' = x\<^sub>2`]])
          apply (rule sym)
          apply (field y1 y2)
          apply (simp_all add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          done
      qed
    qed
  next
    case (Gen p\<^sub>3 x\<^sub>3 y\<^sub>3 p\<^sub>5 x\<^sub>5 y\<^sub>5 p\<^sub>6 x\<^sub>6 y\<^sub>6 l\<^sub>1)
    then show ?case by (simp add: is_tangent_def)
  qed
qed

lemma spec3_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and "is_generic p\<^sub>1 p\<^sub>2"
  and "is_tangent p\<^sub>2 p\<^sub>3"
  and "is_generic (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  and "is_tangent p\<^sub>1 (add a p\<^sub>2 p\<^sub>3)"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  using a b p\<^sub>1 p\<^sub>2 assms
proof (induct rule: add_case)
  case InfL
  then show ?case by (simp add: is_generic_def)
next
  case InfR
  then show ?case by (simp add: is_generic_def)
next
  case Opp
  then show ?case by (simp add: is_generic_def)
next
  case Tan
  then show ?case by (simp add: is_generic_def)
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>4 x\<^sub>4 y\<^sub>4 l)
  with a b `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>3`
  show ?case
  proof (induct rule: add_case)
    case InfL
    then show ?case by (simp add: is_generic_def)
  next
    case InfR
    then show ?case by (simp add: is_generic_def)
  next
    case Opp
    then show ?case by (simp add: is_tangent_def opp_opp)
  next
    case (Tan p\<^sub>2 x\<^sub>2' y\<^sub>2' p\<^sub>5 x\<^sub>5 y\<^sub>5 l\<^sub>1)
    from a b `on_curve a b p\<^sub>2` `p\<^sub>5 = add a p\<^sub>2 p\<^sub>2`
    have "on_curve a b p\<^sub>5" by (simp add: add_closed)
    with a b `on_curve a b p\<^sub>1` show ?case using Tan
    proof (induct rule: add_case)
      case InfL
      then show ?case by (simp add: is_generic_def)
    next
      case InfR
      then show ?case by (simp add: is_generic_def)
    next
      case Opp
      then show ?case by (simp add: is_tangent_def opp_opp)
    next
      case (Tan p\<^sub>1 x\<^sub>1' y\<^sub>1' p\<^sub>6 x\<^sub>6 y\<^sub>6 l\<^sub>2)
      from a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2`
      have "on_curve a b p\<^sub>4" by (simp add: add_closed)
      with a b show ?case using `on_curve a b p\<^sub>2` Tan
      proof (induct rule: add_case)
        case InfL
        then show ?case by (simp add: is_generic_def)
      next
        case InfR
        then show ?case by (simp add: is_generic_def)
      next
        case (Opp p)
        from `is_generic p (opp p)` `on_curve a b p`
        show ?case by (simp add: is_generic_def opp_opp)
      next
        case Tan
        then show ?case by (simp add: is_generic_def)
      next
        case (Gen p\<^sub>4' x\<^sub>4' y\<^sub>4' p\<^sub>2' x\<^sub>2'' y\<^sub>2'' p\<^sub>7 x\<^sub>7 y\<^sub>7 l\<^sub>3)
        from
          `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
          `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
        have
          "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" and y1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b" and
          "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R" and y2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
          by (simp_all add: on_curve_def)
        from
          `p\<^sub>4' = Point x\<^sub>4' y\<^sub>4'`
          `p\<^sub>4' = Point x\<^sub>4 y\<^sub>4`
          `p\<^sub>2' = Point x\<^sub>2' y\<^sub>2'`
          `p\<^sub>2' = Point x\<^sub>2 y\<^sub>2`
          `p\<^sub>2' = Point x\<^sub>2'' y\<^sub>2''`
          `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'`
          `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
          `p\<^sub>1 = Point x\<^sub>5 y\<^sub>5`
        have ps:
          "x\<^sub>4' = x\<^sub>4" "y\<^sub>4' = y\<^sub>4" "x\<^sub>2' = x\<^sub>2" "y\<^sub>2' = y\<^sub>2" "x\<^sub>2'' = x\<^sub>2" "y\<^sub>2'' = y\<^sub>2"
          "x\<^sub>1' = x\<^sub>5" "y\<^sub>1' = y\<^sub>5" "x\<^sub>1 = x\<^sub>5" "y\<^sub>1 = y\<^sub>5"
          by simp_all
        note qs =
          `x\<^sub>7 = l\<^sub>3 (^) 2 \<ominus> x\<^sub>4' \<ominus> x\<^sub>2''`
          `y\<^sub>7 = \<ominus> y\<^sub>4' \<ominus> l\<^sub>3 \<otimes> (x\<^sub>7 \<ominus> x\<^sub>4')`
          `l\<^sub>3 = (y\<^sub>2'' \<ominus> y\<^sub>4') \<oslash> (x\<^sub>2'' \<ominus> x\<^sub>4')`
          `x\<^sub>6 = l\<^sub>2 (^) 2 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>1'`
          `y\<^sub>6 = \<ominus> y\<^sub>1' \<ominus> l\<^sub>2 \<otimes> (x\<^sub>6 \<ominus> x\<^sub>1')`
          `x\<^sub>5 = l\<^sub>1 (^) 2 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2'`
          `y\<^sub>5 = \<ominus> y\<^sub>2' \<ominus> l\<^sub>1 \<otimes> (x\<^sub>5 \<ominus> x\<^sub>2')`
          `l\<^sub>1 = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2' (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2')`
          `l\<^sub>2 = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1' (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>1')`
          `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`
          `y\<^sub>4 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1)`
          `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`
        from `y\<^sub>2 \<in> carrier R` `y\<^sub>2' \<noteq> \<zero>` `y\<^sub>2' = y\<^sub>2`
        have "\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>" by (simp add: integral_iff)
        show ?case
          apply (simp add: `p\<^sub>6 = Point x\<^sub>6 y\<^sub>6` `p\<^sub>7 = Point x\<^sub>7 y\<^sub>7`)
          apply (simp only: ps qs)
          apply (rule conjI)
          apply (field y2)
          apply (intro conjI)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `y\<^sub>1' \<noteq> \<zero>`])
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>4' \<noteq> x\<^sub>2''`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (intro conjI)
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (erule thin_rl)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (field y2)
          apply (intro conjI)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `y\<^sub>1' \<noteq> \<zero>`])
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>4' \<noteq> x\<^sub>2''`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (erule thin_rl)
          apply (rule conjI)
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          apply (rule notI)
          apply (ring (prems))
          apply (rule notE [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
          apply (rule sym)
          apply (simp only: ps qs)
          apply field
          apply (rule `\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<noteq> \<zero>`)
          done
      qed
    next
      case Gen
      then show ?case by (simp add: is_tangent_def)
    qed
  next
    case Gen
    then show ?case by (simp add: is_tangent_def)
  qed
qed

lemma add_0_l: "add a Infinity p = p"
  by (simp add: add_def)

lemma add_0_r: "add a p Infinity = p"
  by (simp add: add_def split add: point.split)

lemma add_opp: "on_curve a b p \<Longrightarrow> add a p (opp p) = Infinity"
  by (simp add: add_def opp_def on_curve_def split add: point.split_asm)

lemma add_comm:
  assumes "a \<in> carrier R" "b \<in> carrier R" "on_curve a b p\<^sub>1" "on_curve a b p\<^sub>2"
  shows "add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>2 p\<^sub>1"
proof (cases p\<^sub>1)
  case Infinity
  then show ?thesis by (simp add: add_0_l add_0_r)
next
  case (Point x\<^sub>1 y\<^sub>1)
  note Point' = this
  with `on_curve a b p\<^sub>1`
  have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
    and y1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
    by (simp_all add: on_curve_def)
  show ?thesis
  proof (cases p\<^sub>2)
    case Infinity
    then show ?thesis by (simp add: add_0_l add_0_r)
  next
    case (Point x\<^sub>2 y\<^sub>2)
    with `on_curve a b p\<^sub>2` have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
      and y2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
      by (simp_all add: on_curve_def)
    show ?thesis
    proof (cases "x\<^sub>1 = x\<^sub>2")
      case True
      show ?thesis
      proof (cases "y\<^sub>1 = \<ominus> y\<^sub>2")
        case True
        with Point Point' `x\<^sub>1 = x\<^sub>2` `y\<^sub>2 \<in> carrier R` show ?thesis
          by (simp add: add_def)
      next
        case False
        with y1 y2 [symmetric] `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R` `x\<^sub>1 = x\<^sub>2` Point Point'
        show ?thesis
          by (simp add: power2_eq_square square_eq_iff)
      qed
    next
      case False
      with Point Point' show ?thesis
        apply (simp add: add_def Let_def)
        apply (rule conjI)
        apply field
        apply (cut_tac `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R`)
        apply (simp add: eq_diff0)
        apply field
        apply (cut_tac `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R`)
        apply (simp add: eq_diff0)
        done
    qed
  qed
qed

lemma uniq_opp:
  assumes "on_curve a b p\<^sub>2"
  and "add a p\<^sub>1 p\<^sub>2 = Infinity"
  shows "p\<^sub>2 = opp p\<^sub>1"
  using assms
  by (auto simp add: on_curve_def add_def opp_def Let_def
    split add: point.split_asm split_if_asm)

lemma uniq_zero:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and add: "add a p\<^sub>1 p\<^sub>2 = p\<^sub>2"
  shows "p\<^sub>1 = Infinity"
  using a b p\<^sub>1 p\<^sub>2 assms
proof (induct rule: add_case)
  case InfL
  show ?case ..
next
  case InfR
  then show ?case by simp
next
  case Opp
  then show ?case by (simp add: opp_def split add: point.split_asm)
next
  case (Tan p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l)
  from `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
  have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" by (simp_all add: on_curve_def)
  with a `l = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) 2 \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>1)` `y\<^sub>1 \<noteq> \<zero>`
  have "l \<in> carrier R" by (simp add: integral_iff)
  from `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>2 = p\<^sub>1`
  have "x\<^sub>2 = x\<^sub>1" "y\<^sub>2 = y\<^sub>1" by simp_all
  with `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R` `l \<in> carrier R` `y\<^sub>2 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>2 \<ominus> x\<^sub>1)` `y\<^sub>1 \<noteq> \<zero>`
  have "\<ominus> y\<^sub>1 = y\<^sub>1" by (simp add: r_neg minus_eq)
  with `y\<^sub>1 \<in> carrier R` `y\<^sub>1 \<noteq> \<zero>`
  show ?case by (simp add: neg_equal_zero)
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
  then have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
    and y1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
    and y2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
    by (simp_all add: on_curve_def)
  with `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)` `x\<^sub>1 \<noteq> x\<^sub>2`
  have "l \<in> carrier R" by (simp add: eq_diff0)
  from `p\<^sub>3 = p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
  have ps: "x\<^sub>3 = x\<^sub>2" "y\<^sub>3 = y\<^sub>2" by simp_all
  with `y\<^sub>3 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1)`
  have "y\<^sub>2 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>2 \<ominus> x\<^sub>1)" by simp
  also from `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)` `x\<^sub>1 \<noteq> x\<^sub>2`
    `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R`
  have "l \<otimes> (x\<^sub>2 \<ominus> x\<^sub>1) = y\<^sub>2 \<ominus> y\<^sub>1"
    by (simp add: m_div_def m_assoc eq_diff0)
  also from `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R`
  have "\<ominus> y\<^sub>1 \<ominus> (y\<^sub>2 \<ominus> y\<^sub>1) = (\<ominus> y\<^sub>1 \<oplus> y\<^sub>1) \<oplus> \<ominus> y\<^sub>2"
    by (simp add: minus_eq minus_add a_ac)
  finally have "y\<^sub>2 = \<zero>" using `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R`
    by (simp add: l_neg equal_neg_zero)
  with `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `on_curve a b p\<^sub>2`
    `a \<in> carrier R` `b \<in> carrier R` `x\<^sub>2 \<in> carrier R`
  have x2: "x\<^sub>2 (^) (3::nat) = \<ominus> (a \<otimes> x\<^sub>2 \<oplus> b)"
    by (simp add: on_curve_def nat_pow_zero eq_neg_iff_add_eq_0 a_assoc)
  from `x\<^sub>3 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2` `x\<^sub>3 = x\<^sub>2`
  have "l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2 \<ominus> x\<^sub>2 = x\<^sub>2 \<ominus> x\<^sub>2" by simp
  with `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `l \<in> carrier R`
  have "l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2 = \<zero>"
    by (simp add: of_int_2 l_distr minus_eq a_ac minus_add r_neg)
  then have "x\<^sub>2 \<otimes> (l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2) = x\<^sub>2 \<otimes> \<zero>" by simp
  then have "(x\<^sub>2 \<ominus> x\<^sub>1) \<otimes> (\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 \<oplus> \<guillemotleft>3\<guillemotright> \<otimes> b) = \<zero>"
    apply (simp add: `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)` `y\<^sub>2 = \<zero>`)
    apply (field (prems) y1 x2)
    apply (ring y1 x2)
    apply (simp add: eq_diff0 `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`])
    done
  with not_sym [OF `x\<^sub>1 \<noteq> x\<^sub>2`]
    `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R` `a \<in> carrier R` `b \<in> carrier R`
  have "\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 \<oplus> \<guillemotleft>3\<guillemotright> \<otimes> b = \<zero>"
    by (simp add: integral_iff eq_diff0)
  with `a \<in> carrier R` `b \<in> carrier R` `x\<^sub>2 \<in> carrier R`
  have "\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 = \<ominus> (\<guillemotleft>3\<guillemotright> \<otimes> b)"
    by (simp add: eq_neg_iff_add_eq_0)
  from y2 [symmetric] `y\<^sub>2 = \<zero>` `a \<in> carrier R`
  have "\<ominus> (\<guillemotleft>2\<guillemotright> \<otimes> a) (^) (3::nat) \<otimes> (x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b) = \<zero>"
    by (simp add: nat_pow_zero)
  then have "b \<otimes> (\<guillemotleft>4\<guillemotright> \<otimes> a (^) (3::nat) \<oplus> \<guillemotleft>27\<guillemotright> \<otimes> b (^) (2::nat)) = \<zero>"
    apply (ring (prems) `\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 = \<ominus> (\<guillemotleft>3\<guillemotright> \<otimes> b)`)
    apply (ring `\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 = \<ominus> (\<guillemotleft>3\<guillemotright> \<otimes> b)`)
    done
  with ab a b have "b = \<zero>" by (simp add: nonsingular_def integral_iff)
  with `\<guillemotleft>2\<guillemotright> \<otimes> a \<otimes> x\<^sub>2 \<oplus> \<guillemotleft>3\<guillemotright> \<otimes> b = \<zero>` ab a b `x\<^sub>2 \<in> carrier R`
  have "x\<^sub>2 = \<zero>" by (simp add: nonsingular_def nat_pow_zero integral_iff)
  from `l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2 = \<zero>`
  show ?case
    apply (simp add: `x\<^sub>2 = \<zero>` `y\<^sub>2 = \<zero>` `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`)
    apply (field (prems) y1 `b = \<zero>`)
    apply (insert a b ab `x\<^sub>1 \<in> carrier R` `b = \<zero>` `x\<^sub>1 \<noteq> x\<^sub>2` `x\<^sub>2 = \<zero>`)
    apply (simp add: nonsingular_def nat_pow_zero integral_iff)
    apply (simp add: trans [OF eq_commute eq_neg_iff_add_eq_0])
    done
qed

lemma opp_add:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  shows "opp (add a p\<^sub>1 p\<^sub>2) = add a (opp p\<^sub>1) (opp p\<^sub>2)"
proof (cases p\<^sub>1)
  case Infinity
  then show ?thesis by (simp add: add_def opp_def)
next
  case (Point x\<^sub>1 y\<^sub>1)
  show ?thesis
  proof (cases p\<^sub>2)
    case Infinity
    with `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` show ?thesis
      by (simp add: add_def opp_def)
  next
    case (Point x\<^sub>2 y\<^sub>2)
    with `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` p\<^sub>1 p\<^sub>2
    have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" "x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b = y\<^sub>1 (^) (2::nat)"
      "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R" "x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b = y\<^sub>2 (^) (2::nat)"
      by (simp_all add: on_curve_def)
    with Point `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` show ?thesis
      apply (cases "x\<^sub>1 = x\<^sub>2")
      apply (cases "y\<^sub>1 = \<ominus> y\<^sub>2")
      apply (simp add: add_def opp_def Let_def)
      apply (simp add: add_def opp_def Let_def neg_equal_swap)
      apply (rule conjI)
      apply field
      apply (auto simp add: integral_iff nat_pow_zero
        trans [OF eq_commute eq_neg_iff_add_eq_0])[1]
      apply field
      apply (auto simp add: integral_iff nat_pow_zero
        trans [OF eq_commute eq_neg_iff_add_eq_0])[1]
      apply (simp add: add_def opp_def Let_def)
      apply (rule conjI)
      apply field
      apply (simp add: eq_diff0)
      apply field
      apply (simp add: eq_diff0)
      done
  qed
qed

lemma compat_add_opp:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and "add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>1 (opp p\<^sub>2)"
  and "p\<^sub>1 \<noteq> opp p\<^sub>1"
  shows "p\<^sub>2 = opp p\<^sub>2"
  using a b p\<^sub>1 p\<^sub>2 assms
proof (induct rule: add_case)
  case InfL
  then show ?case by (simp add: add_0_l)
next
  case InfR
  then show ?case by (simp add: opp_def add_0_r)
next
  case (Opp p)
  then have "add a p p = Infinity" by (simp add: opp_opp)
  with `on_curve a b p` have "p = opp p" by (rule uniq_opp)
  with `p \<noteq> opp p` show ?case ..
next
  case (Tan p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l)
  then have "add a p\<^sub>1 p\<^sub>1 = Infinity"
    by (simp add: add_opp)
  with `on_curve a b p\<^sub>1` have "p\<^sub>1 = opp p\<^sub>1" by (rule uniq_opp)
  with `p\<^sub>1 \<noteq> opp p\<^sub>1` show ?case ..
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
  then have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
    by (simp_all add: on_curve_def)
  have "\<guillemotleft>2\<guillemotright> \<otimes> \<guillemotleft>2\<guillemotright> \<noteq> \<zero>"
    by (simp add: integral_iff)
  then have "\<guillemotleft>4\<guillemotright> \<noteq> \<zero>" by (simp add: of_int_mult [symmetric])
  from Gen have "((\<ominus> y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)) (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2 =
    ((y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)) (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2"
    by (simp add: add_def opp_def Let_def)
  then show ?case
    apply (field (prems))
    apply (insert `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R` `p\<^sub>1 \<noteq> opp p\<^sub>1`
      `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `\<guillemotleft>4\<guillemotright> \<noteq> \<zero>`)[1]
    apply (simp add: integral_iff opp_def eq_neg_iff_add_eq_0 mult2)
    apply (insert `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<noteq> x\<^sub>2`)
    apply (simp add: eq_diff0)
    done
qed

lemma compat_add_triple:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p: "on_curve a b p"
  and "p \<noteq> opp p"
  and "add a p p \<noteq> opp p"
  shows "add a (add a p p) (opp p) = p"
  using a b add_closed [OF a b p p] opp_closed [OF p] assms
proof (induct "add a p p" "opp p" rule: add_case)
  case InfL
  from `p \<noteq> opp p` uniq_opp [OF p `Infinity = add a p p` [symmetric]]
  show ?case ..
next
  case InfR
  then show ?case by (simp add: opp_def split add: point.split_asm)
next
  case Opp
  then have "opp (opp (add a p p)) = opp (opp p)" by simp
  with `on_curve a b (add a p p)` `on_curve a b p`
  have "add a p p = p" by (simp add: opp_opp)
  with uniq_zero [OF a b ab p p] `p \<noteq> opp p`
  show ?case by (simp add: opp_def)
next
  case Tan
  then show ?case by simp
next
  case (Gen x\<^sub>1 y\<^sub>1 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
  with opp_closed [OF p]
  have  "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
    by (simp_all add: on_curve_def)
  from `opp p = Point x\<^sub>2 y\<^sub>2` p
  have "p = Point x\<^sub>2 (\<ominus> y\<^sub>2)"
    by (auto simp add: opp_def on_curve_def neg_equal_swap split add: point.split_asm)
  with `add a p p = Point x\<^sub>1 y\<^sub>1` [symmetric]
  obtain l' where l':
    "l' = (\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> \<ominus> y\<^sub>2)"
    and xy: "x\<^sub>1 = l' (^) (2::nat) \<ominus> \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>2"
    "y\<^sub>1 = \<ominus> (\<ominus> y\<^sub>2) \<ominus> l' \<otimes> (x\<^sub>1 \<ominus> x\<^sub>2)"
    and y2: "\<ominus> y\<^sub>2 \<noteq> \<ominus> (\<ominus> y\<^sub>2)"
    by (simp add: add_def Let_def split add: split_if_asm)
  from l' `x\<^sub>2 \<in> carrier R` `y\<^sub>2 \<in> carrier R` a y2
  have "l' \<in> carrier R" by (simp add: neg_equal_zero neg_equal_swap integral_iff)
  have "x\<^sub>3 = x\<^sub>2"
    apply (simp add: xy
      `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)` `x\<^sub>3 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2`)
    apply field
    apply (insert `x\<^sub>1 \<noteq> x\<^sub>2` `x\<^sub>2 \<in> carrier R` `l' \<in> carrier R`)
    apply (simp add: xy eq_diff0)
    done
  then have "p\<^sub>3 = p \<or> p\<^sub>3 = opp p"
    by (rule curve_elt_opp [OF `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3` `p = Point x\<^sub>2 (\<ominus> y\<^sub>2)`
      add_closed [OF a b add_closed [OF a b p p] opp_closed [OF p],
        folded `p\<^sub>3 = add a (add a p p) (opp p)`]
     `on_curve a b p`])
  then show ?case
  proof
    assume "p\<^sub>3 = p"
    with `p\<^sub>3 = add a (add a p p) (opp p)`
    show ?thesis by simp
  next
    assume "p\<^sub>3 = opp p"
    with `p\<^sub>3 = add a (add a p p) (opp p)`
    have "add a (add a p p) (opp p) = opp p" by simp
    with a b ab add_closed [OF a b p p] opp_closed [OF p]
    have "add a p p = Infinity" by (rule uniq_zero)
    with `add a p p = Point x\<^sub>1 y\<^sub>1` show ?thesis by simp
  qed
qed

lemma add_opp_double_opp:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and "add a p\<^sub>1 p\<^sub>2 = opp p\<^sub>1"
  shows "p\<^sub>2 = add a (opp p\<^sub>1) (opp p\<^sub>1)"
proof (cases "p\<^sub>1 = opp p\<^sub>1")
  case True
  with assms have "add a p\<^sub>2 p\<^sub>1 = p\<^sub>1" by (simp add: add_comm)
  with a b ab p\<^sub>2 p\<^sub>1 have "p\<^sub>2 = Infinity" by (rule uniq_zero)
  also from `on_curve a b p\<^sub>1` have "\<dots> = add a p\<^sub>1 (opp p\<^sub>1)"
    by (simp add: add_opp)
  also from True have "\<dots> = add a (opp p\<^sub>1) (opp p\<^sub>1)" by simp
  finally show ?thesis .
next
  case False
  from a b p\<^sub>1 p\<^sub>2 False assms show ?thesis
  proof (induct rule: add_case)
    case InfL
    then show ?case by simp
  next
    case InfR
    then show ?case by simp
  next
    case Opp
    then show ?case by (simp add: add_0_l)
  next
    case (Tan p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l)
    from `p\<^sub>2 = opp p\<^sub>1` `on_curve a b p\<^sub>1`
    have "p\<^sub>1 = opp p\<^sub>2" by (simp add: opp_opp)
    also note `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1`
    finally show ?case using a b `on_curve a b p\<^sub>1`
      by (simp add: opp_add)
  next
    case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
    from `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
    have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
      and y\<^sub>1: "y\<^sub>1 (^) (2::nat) = x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<oplus> b"
      by (simp_all add: on_curve_def)
    from `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
    have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
      and y\<^sub>2: "y\<^sub>2 (^) (2::nat) = x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<oplus> b"
      by (simp_all add: on_curve_def)
    from `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>1 \<noteq> opp p\<^sub>1` `y\<^sub>1 \<in> carrier R`
    have "y\<^sub>1 \<noteq> \<zero>"
      by (simp add: opp_Point integral_iff equal_neg_zero)
    from Gen have "x\<^sub>1 = ((y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)) (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2"
      by (simp add: opp_Point)
    then have "\<guillemotleft>2\<guillemotright> \<otimes> y\<^sub>2 \<otimes> y\<^sub>1 = a \<otimes> x\<^sub>2 \<oplus> \<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>2 \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a \<otimes> x\<^sub>1 \<ominus>
      x\<^sub>1 (^) (3::nat) \<oplus> \<guillemotleft>2\<guillemotright> \<otimes> b"
      apply (field (prems) y\<^sub>1 y\<^sub>2)
      apply (field y\<^sub>1 y\<^sub>2)
      apply simp
      apply (insert `x\<^sub>1 \<noteq> x\<^sub>2` `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R`)
      apply (simp add: eq_diff0)
      done
    then have "(x\<^sub>2 \<ominus> (((\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> (\<ominus> y\<^sub>1))) (^) (2::nat) \<ominus>
      \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>1)) \<otimes> (x\<^sub>2 \<ominus> x\<^sub>1) (^) (2::nat) = \<zero>"
      apply (drule_tac f="\<lambda>x. x (^) (2::nat)" in arg_cong)
      apply (field (prems) y\<^sub>1 y\<^sub>2)
      apply (field y\<^sub>1 y\<^sub>2)
      apply (insert `y\<^sub>1 \<noteq> \<zero>` `y\<^sub>1 \<in> carrier R`)
      apply (simp_all add: integral_iff neg_equal_swap)
      done
    with a `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R`
      `y\<^sub>1 \<noteq> \<zero>` `x\<^sub>1 \<noteq> x\<^sub>2`
    have "x\<^sub>2 = ((\<guillemotleft>3\<guillemotright> \<otimes> x\<^sub>1 (^) (2::nat) \<oplus> a) \<oslash> (\<guillemotleft>2\<guillemotright> \<otimes> (\<ominus> y\<^sub>1))) (^) (2::nat) \<ominus>
      \<guillemotleft>2\<guillemotright> \<otimes> x\<^sub>1"
      by (simp add: integral_iff eq_diff0 neg_equal_swap)
    with `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` _ `on_curve a b p\<^sub>2`
      add_closed [OF a b
        opp_closed [OF `on_curve a b p\<^sub>1`] opp_closed [OF `on_curve a b p\<^sub>1`]]
    have "p\<^sub>2 = add a (opp p\<^sub>1) (opp p\<^sub>1) \<or> p\<^sub>2 = opp (add a (opp p\<^sub>1) (opp p\<^sub>1))"
      apply (rule curve_elt_opp)
      apply (insert `y\<^sub>1 \<in> carrier R` `y\<^sub>1 \<noteq> \<zero>`)
      apply (simp add: add_def opp_Point neg_equal_zero Let_def `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`)
      done
    then show ?case
    proof
      assume "p\<^sub>2 = opp (add a (opp p\<^sub>1) (opp p\<^sub>1))"
      with a b `on_curve a b p\<^sub>1`
      have "p\<^sub>2 = add a p\<^sub>1 p\<^sub>1"
        by (simp add: opp_add opp_opp opp_closed)
      show ?case
      proof (cases "add a p\<^sub>1 p\<^sub>1 = opp p\<^sub>1")
        case True
        from a b `on_curve a b p\<^sub>1`
        show ?thesis
          apply (simp add: opp_add [symmetric] `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1` True)
          apply (simp add: `p\<^sub>3 = add a p\<^sub>1 p\<^sub>2` [simplified `p\<^sub>3 = opp p\<^sub>1`])
          apply (simp add: `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1` True add_opp)
          done
      next
        case False
        from a b `on_curve a b p\<^sub>1`
        have "add a p\<^sub>1 (opp p\<^sub>2) = opp (add a (add a p\<^sub>1 p\<^sub>1) (opp p\<^sub>1))"
          by (simp add: `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1`
            opp_add add_closed opp_closed opp_opp add_comm)
        with a b ab `on_curve a b p\<^sub>1` `p\<^sub>1 \<noteq> opp p\<^sub>1` False
        have "add a p\<^sub>1 (opp p\<^sub>2) = opp p\<^sub>1"
          by (simp add: compat_add_triple)
        with `p\<^sub>3 = add a p\<^sub>1 p\<^sub>2` `p\<^sub>3 = opp p\<^sub>1`
        have "add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>1 (opp p\<^sub>2)" by simp
        with a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`
        have "p\<^sub>2 = opp p\<^sub>2" using `p\<^sub>1 \<noteq> opp p\<^sub>1`
          by (rule compat_add_opp)
        with a b `on_curve a b p\<^sub>1` `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1`
        show ?thesis by (simp add: opp_add)
      qed
    qed
  qed
qed

lemma cancel:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and eq: "add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>1 p\<^sub>3"
  shows "p\<^sub>2 = p\<^sub>3"
  using a b p\<^sub>1 p\<^sub>2 p\<^sub>1 p\<^sub>2 eq
proof (induct rule: add_casew)
  case InfL
  then show ?case by (simp add: add_0_l)
next
  case (InfR p)
  with a b p\<^sub>3 have "add a p\<^sub>3 p = p" by (simp add: add_comm)
  with a b ab p\<^sub>3 `on_curve a b p`
  show ?case by (rule uniq_zero [symmetric])
next
  case (Opp p)
  from p\<^sub>3 `Infinity = add a p p\<^sub>3` [symmetric]
  show ?case by (rule uniq_opp [symmetric])
next
  case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>4 x\<^sub>4 y\<^sub>4 l)
  from `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
  have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
    by (simp_all add: on_curve_def)
  from `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
  have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
    by (simp_all add: on_curve_def)
  from add_closed [OF a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`]
    `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2` [symmetric] `p\<^sub>4 = Point x\<^sub>4 y\<^sub>4`
  have "x\<^sub>4 \<in> carrier R" "y\<^sub>4 \<in> carrier R"
    by (simp_all add: on_curve_def)
  from `_ \<or> _` a `p\<^sub>1 \<noteq> opp p\<^sub>2` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
    `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R`
    `x\<^sub>2 \<in> carrier R` `y\<^sub>2 \<in> carrier R`
  have "l \<in> carrier R"
    by (auto simp add: opp_Point equal_neg_zero integral_iff eq_diff0)
  from a b `on_curve a b p\<^sub>1` p\<^sub>3 `on_curve a b p\<^sub>1` p\<^sub>3 `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
    `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>3` `p\<^sub>1 \<noteq> opp p\<^sub>2`
  show ?case
  proof (induct rule: add_casew)
    case InfL
    then show ?case by (simp add: add_0_l)
  next
    case (InfR p)
    with a b `on_curve a b p\<^sub>2`
    have "add a p\<^sub>2 p = p" by (simp add: add_comm)
    with a b ab `on_curve a b p\<^sub>2` `on_curve a b p`
    show ?case by (rule uniq_zero)
  next
    case (Opp p)
    then have "add a p p\<^sub>2 = Infinity" by simp
    with `on_curve a b p\<^sub>2` show ?case by (rule uniq_opp)
  next
    case (Gen p\<^sub>1 x\<^sub>1' y\<^sub>1' p\<^sub>3 x\<^sub>3 y\<^sub>3 p\<^sub>5 x\<^sub>5 y\<^sub>5 l')
    from `on_curve a b p\<^sub>3` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
    have "x\<^sub>3 \<in> carrier R" "y\<^sub>3 \<in> carrier R"
      by (simp_all add: on_curve_def)
    from `x\<^sub>1' = x\<^sub>3 \<and> _ \<or> _` a `p\<^sub>1 \<noteq> opp p\<^sub>3`
      `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
      `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R`
      `x\<^sub>3 \<in> carrier R` `y\<^sub>3 \<in> carrier R`
    have "l' \<in> carrier R"
      by (auto simp add: opp_Point equal_neg_zero integral_iff eq_diff0)
    from `p\<^sub>4 = p\<^sub>5` `p\<^sub>4 = Point x\<^sub>4 y\<^sub>4` `p\<^sub>5 = Point x\<^sub>5 y\<^sub>5`
      `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
      `y\<^sub>4 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1)` `y\<^sub>5 = \<ominus> y\<^sub>1' \<ominus> l' \<otimes> (x\<^sub>5 \<ominus> x\<^sub>1')`
      `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R` `x\<^sub>4 \<in> carrier R` `l' \<in> carrier R`
    have "\<zero> = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1) \<ominus> (\<ominus> y\<^sub>1 \<ominus> l' \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1))"
      by (auto simp add: trans [OF eq_commute eq_diff0])
    with `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R` `x\<^sub>4 \<in> carrier R`
      `l \<in> carrier R` `l' \<in> carrier R`
    have "(l' \<ominus> l) \<otimes> (x\<^sub>4 \<ominus> x\<^sub>1) = \<zero>"
      apply simp
      apply (rule eq_diff0 [THEN iffD1])
      apply simp
      apply simp
      apply ring
      done
    with `x\<^sub>1 \<in> carrier R` `x\<^sub>4 \<in> carrier R` `l \<in> carrier R` `l' \<in> carrier R`
    have "l' = l \<or> x\<^sub>4 = x\<^sub>1"
      by (simp add: integral_iff eq_diff0)
    then show ?case
    proof
      assume "l' = l"
      with `p\<^sub>4 = p\<^sub>5` `p\<^sub>4 = Point x\<^sub>4 y\<^sub>4` `p\<^sub>5 = Point x\<^sub>5 y\<^sub>5`
        `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
        `x\<^sub>4 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2` `x\<^sub>5 = l' (^) 2 \<ominus> x\<^sub>1' \<ominus> x\<^sub>3`
        `x\<^sub>1 \<in> carrier R` `x\<^sub>3 \<in> carrier R` `l \<in> carrier R`
      have "\<zero> = l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>2 \<ominus> (l (^) (2::nat) \<ominus> x\<^sub>1 \<ominus> x\<^sub>3)"
        by (simp add: trans [OF eq_commute eq_diff0])
      with `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `x\<^sub>3 \<in> carrier R` `l \<in> carrier R`
      have "x\<^sub>2 = x\<^sub>3"
        apply (rule_tac eq_diff0 [THEN iffD1, THEN sym])
        apply simp_all
        apply (rule eq_diff0 [THEN iffD1])
        apply simp_all[2]
        apply ring
        done
      with `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3` `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>3`
      have "p\<^sub>2 = p\<^sub>3 \<or> p\<^sub>2 = opp p\<^sub>3" by (rule curve_elt_opp)
      then show ?case
      proof
        assume "p\<^sub>2 = opp p\<^sub>3"
        with `on_curve a b p\<^sub>3` have "opp p\<^sub>2 = p\<^sub>3"
          by (simp add: opp_opp)
        with `p\<^sub>4 = p\<^sub>5` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2` `p\<^sub>5 = add a p\<^sub>1 p\<^sub>3`
        have "add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>1 (opp p\<^sub>2)" by simp
        show ?case
        proof (cases "p\<^sub>1 = opp p\<^sub>1")
          case True
          with `p\<^sub>1 \<noteq> opp p\<^sub>2` `p\<^sub>1 \<noteq> opp p\<^sub>3`
          have "p\<^sub>1 \<noteq> p\<^sub>2" "p\<^sub>1 \<noteq> p\<^sub>3" by auto
          with `l' = l` `x\<^sub>1 = x\<^sub>2 \<and> _\<or> _` `x\<^sub>1' = x\<^sub>3 \<and> _ \<or> _`
            `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1` `p\<^sub>1 = Point x\<^sub>1' y\<^sub>1'`
            `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
            `p\<^sub>2 = opp p\<^sub>3`
          have eq: "(y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1) = (y\<^sub>3 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)" and "x\<^sub>1 \<noteq> x\<^sub>2"
            by (auto simp add: opp_Point)
          from eq have "y\<^sub>2 = y\<^sub>3"
            apply (field (prems))
            apply (rule eq_diff0 [THEN iffD1])
            apply (insert `x\<^sub>1 \<noteq> x\<^sub>2` `x\<^sub>1 \<in> carrier R` `y\<^sub>1 \<in> carrier R`
              `x\<^sub>2 \<in> carrier R` `y\<^sub>2 \<in> carrier R` `y\<^sub>3 \<in> carrier R`)
            apply simp_all
            apply (erule subst)
            apply (rule eq_diff0 [THEN iffD1])
            apply simp_all
            apply ring
            apply (simp add: eq_diff0)
            done
          with `p\<^sub>2 = opp p\<^sub>3` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>3 = Point x\<^sub>3 y\<^sub>3`
          show ?thesis by (simp add: opp_Point)
        next
          case False
          with a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`
            `add a p\<^sub>1 p\<^sub>2 = add a p\<^sub>1 (opp p\<^sub>2)`
          have "p\<^sub>2 = opp p\<^sub>2" by (rule compat_add_opp)
          with `opp p\<^sub>2 = p\<^sub>3` show ?thesis by simp
        qed
      qed
    next
      assume "x\<^sub>4 = x\<^sub>1"
      with `p\<^sub>4 = Point x\<^sub>4 y\<^sub>4` [simplified `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2`]
        `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
        add_closed [OF a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`]
        `on_curve a b p\<^sub>1`
      have "add a p\<^sub>1 p\<^sub>2 = p\<^sub>1 \<or> add a p\<^sub>1 p\<^sub>2 = opp p\<^sub>1" by (rule curve_elt_opp)
      then show ?case
      proof
        assume "add a p\<^sub>1 p\<^sub>2 = p\<^sub>1"
        with a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`
        have "add a p\<^sub>2 p\<^sub>1 = p\<^sub>1" by (simp add: add_comm)
        with a b ab `on_curve a b p\<^sub>2` `on_curve a b p\<^sub>1`
        have "p\<^sub>2 = Infinity" by (rule uniq_zero)
        moreover from `add a p\<^sub>1 p\<^sub>2 = p\<^sub>1`
          `p\<^sub>4 = p\<^sub>5` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2` `p\<^sub>5 = add a p\<^sub>1 p\<^sub>3`
          a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>3`
        have "add a p\<^sub>3 p\<^sub>1 = p\<^sub>1" by (simp add: add_comm)
        with a b ab `on_curve a b p\<^sub>3` `on_curve a b p\<^sub>1`
        have "p\<^sub>3 = Infinity" by (rule uniq_zero)
        ultimately show ?case by simp
      next
        assume "add a p\<^sub>1 p\<^sub>2 = opp p\<^sub>1"
        with a b ab `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`
        have "p\<^sub>2 = add a (opp p\<^sub>1) (opp p\<^sub>1)" by (rule add_opp_double_opp)
        moreover from `add a p\<^sub>1 p\<^sub>2 = opp p\<^sub>1`
          `p\<^sub>4 = p\<^sub>5` `p\<^sub>4 = add a p\<^sub>1 p\<^sub>2` `p\<^sub>5 = add a p\<^sub>1 p\<^sub>3`
        have "add a p\<^sub>1 p\<^sub>3 = opp p\<^sub>1" by simp
        with a b ab `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>3`
        have "p\<^sub>3 = add a (opp p\<^sub>1) (opp p\<^sub>1)" by (rule add_opp_double_opp)
        ultimately show ?case by simp
      qed
    qed
  qed
qed

lemma add_minus_id:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  shows "add a (add a p\<^sub>1 p\<^sub>2) (opp p\<^sub>2) = p\<^sub>1"
proof (cases "add a p\<^sub>1 p\<^sub>2 = opp p\<^sub>2")
  case True
  then have "add a (add a p\<^sub>1 p\<^sub>2) (opp p\<^sub>2) = add a (opp p\<^sub>2) (opp p\<^sub>2)"
    by simp
  also from a b p\<^sub>1 p\<^sub>2 True have "add a p\<^sub>2 p\<^sub>1 = opp p\<^sub>2"
    by (simp add: add_comm)
  with a b ab p\<^sub>2 p\<^sub>1 have "add a (opp p\<^sub>2) (opp p\<^sub>2) = p\<^sub>1"
    by (rule add_opp_double_opp [symmetric])
  finally show ?thesis .
next
  case False
  from a b p\<^sub>1 p\<^sub>2 p\<^sub>1 p\<^sub>2 False show ?thesis
  proof (induct rule: add_case)
    case InfL
    then show ?case by (simp add: add_opp)
  next
    case InfR
    show ?case by (simp add: add_0_r)
  next
    case Opp
    then show ?case by (simp add: opp_opp add_0_l)
  next
    case (Tan p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 l)
    note a b ab `on_curve a b p\<^sub>1`
    moreover from `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
    have "y\<^sub>1 \<in> carrier R" by (simp add: on_curve_def)
    with `y\<^sub>1 \<noteq> \<zero>` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
    have "p\<^sub>1 \<noteq> opp p\<^sub>1" by (simp add: opp_Point equal_neg_zero)
    moreover from `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1` `p\<^sub>2 \<noteq> opp p\<^sub>1`
    have "add a p\<^sub>1 p\<^sub>1 \<noteq> opp p\<^sub>1" by simp
    ultimately have "add a (add a p\<^sub>1 p\<^sub>1) (opp p\<^sub>1) = p\<^sub>1"
      by (rule compat_add_triple)
    with `p\<^sub>2 = add a p\<^sub>1 p\<^sub>1` show ?case by simp
  next
    case (Gen p\<^sub>1 x\<^sub>1 y\<^sub>1 p\<^sub>2 x\<^sub>2 y\<^sub>2 p\<^sub>3 x\<^sub>3 y\<^sub>3 l)
    from `p\<^sub>3 = add a p\<^sub>1 p\<^sub>2` `on_curve a b p\<^sub>2`
    have "p\<^sub>3 = add a p\<^sub>1 (opp (opp p\<^sub>2))" by (simp add: opp_opp)
    with a b
      add_closed [OF a b `on_curve a b p\<^sub>1` `on_curve a b p\<^sub>2`,
        folded `p\<^sub>3 = add a p\<^sub>1 p\<^sub>2`]
      opp_closed [OF `on_curve a b p\<^sub>2`]
      opp_closed [OF `on_curve a b p\<^sub>2`]
      opp_opp [OF `on_curve a b p\<^sub>2`]
      Gen
    show ?case
    proof (induct rule: add_case)
      case InfL
      then show ?case by simp
    next
      case InfR
      then show ?case by (simp add: add_0_r)
    next
      case (Opp p)
      from `on_curve a b p` `p = add a p\<^sub>1 (opp (opp p))`
      have "add a p\<^sub>1 p = p" by (simp add: opp_opp)
      with a b ab `on_curve a b p\<^sub>1` `on_curve a b p`
      show ?case by (rule uniq_zero [symmetric])
    next
      case Tan
      then show ?case by simp
    next
      case (Gen p\<^sub>4 x\<^sub>4 y\<^sub>4 p\<^sub>5 x\<^sub>5 y\<^sub>5 p\<^sub>6 x\<^sub>6 y\<^sub>6 l')
      from `on_curve a b p\<^sub>1` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
      have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R"
        by (simp_all add: on_curve_def)
      from `on_curve a b p\<^sub>2` `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2`
      have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R"
        by (simp_all add: on_curve_def)
      from `on_curve a b p\<^sub>5` `opp p\<^sub>5 = p\<^sub>2`
        `p\<^sub>2 = Point x\<^sub>2 y\<^sub>2` `p\<^sub>5 = Point x\<^sub>5 y\<^sub>5`
      have "y\<^sub>5 = \<ominus> y\<^sub>2" "x\<^sub>5 = x\<^sub>2"
        by (auto simp add: opp_Point on_curve_def)
      from `p\<^sub>4 = Point x\<^sub>3 y\<^sub>3` `p\<^sub>4 = Point x\<^sub>4 y\<^sub>4`
      have "x\<^sub>4 = x\<^sub>3" "y\<^sub>4 = y\<^sub>3" by simp_all
      from `x\<^sub>4 \<noteq> x\<^sub>5` show ?case
        apply (simp add:
          `y\<^sub>5 = \<ominus> y\<^sub>2` `x\<^sub>5 = x\<^sub>2`
          `x\<^sub>4 = x\<^sub>3` `y\<^sub>4 = y\<^sub>3`
          `p\<^sub>6 = Point x\<^sub>6 y\<^sub>6` `p\<^sub>1 = Point x\<^sub>1 y\<^sub>1`
          `x\<^sub>6 = l' (^) 2 \<ominus> x\<^sub>4 \<ominus> x\<^sub>5` `y\<^sub>6 = \<ominus> y\<^sub>4 \<ominus> l' \<otimes> (x\<^sub>6 \<ominus> x\<^sub>4)`
          `l' = (y\<^sub>5 \<ominus> y\<^sub>4) \<oslash> (x\<^sub>5 \<ominus> x\<^sub>4)`
          `x\<^sub>3 = l (^) 2 \<ominus> x\<^sub>1 \<ominus> x\<^sub>2` `y\<^sub>3 = \<ominus> y\<^sub>1 \<ominus> l \<otimes> (x\<^sub>3 \<ominus> x\<^sub>1)`
          `l = (y\<^sub>2 \<ominus> y\<^sub>1) \<oslash> (x\<^sub>2 \<ominus> x\<^sub>1)`)
        apply (rule conjI)
        apply field
        apply (rule conjI)
        apply (rule notI)
        apply (erule notE)
        apply (ring (prems))
        apply (rule sym)
        apply field
        apply (simp_all add: eq_diff0 [OF `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R`]
          `x\<^sub>1 \<noteq> x\<^sub>2` [THEN not_sym])
        apply field
        apply (rule conjI)
        apply (simp add: eq_diff0 [OF `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R`]
          `x\<^sub>1 \<noteq> x\<^sub>2` [THEN not_sym])
        apply (rule notI)
        apply (erule notE)
        apply (ring (prems))
        apply (rule sym)
        apply field
        apply (simp add: eq_diff0 [OF `x\<^sub>2 \<in> carrier R` `x\<^sub>1 \<in> carrier R`]
          `x\<^sub>1 \<noteq> x\<^sub>2` [THEN not_sym])
        done
    qed
  qed
qed

lemma add_shift_minus:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and eq: "add a p\<^sub>1 p\<^sub>2 = p\<^sub>3"
  shows "p\<^sub>1 = add a p\<^sub>3 (opp p\<^sub>2)"
proof -
  note eq
  also from add_minus_id [OF a b ab p\<^sub>3 opp_closed [OF p\<^sub>2]] p\<^sub>2
  have "p\<^sub>3 = add a (add a p\<^sub>3 (opp p\<^sub>2)) p\<^sub>2" by (simp add: opp_opp)
  finally have "add a p\<^sub>2 p\<^sub>1 = add a p\<^sub>2 (add a p\<^sub>3 (opp p\<^sub>2))"
    using a b p\<^sub>1 p\<^sub>2 p\<^sub>3
    by (simp add: add_comm add_closed opp_closed)
  with a b ab p\<^sub>2 p\<^sub>1 add_closed [OF a b p\<^sub>3 opp_closed [OF p\<^sub>2]]
  show ?thesis by (rule cancel)
qed

lemma degen_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  and H:
    "(p\<^sub>1 = Infinity \<or> p\<^sub>2 = Infinity \<or> p\<^sub>3 = Infinity) \<or>
     (p\<^sub>1 = opp p\<^sub>2 \<or> p\<^sub>2 = opp p\<^sub>3) \<or>
     (opp p\<^sub>1 = add a p\<^sub>2 p\<^sub>3 \<or> opp p\<^sub>3 = add a p\<^sub>1 p\<^sub>2)"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
  using H
proof (elim disjE)
  assume "p\<^sub>1 = Infinity"
  then show ?thesis by (simp add: add_0_l)
next
  assume "p\<^sub>2 = Infinity"
  then show ?thesis by (simp add: add_0_l add_0_r)
next
  assume "p\<^sub>3 = Infinity"
  then show ?thesis by (simp add: add_0_r)
next
  assume "p\<^sub>1 = opp p\<^sub>2"
  from a b p\<^sub>2 p\<^sub>3
  have "add a (opp p\<^sub>2) (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>3 p\<^sub>2) (opp p\<^sub>2)"
    by (simp add: add_comm add_closed opp_closed)
  also from a b ab p\<^sub>3 p\<^sub>2 have "\<dots> = p\<^sub>3" by (rule add_minus_id)
  also have "\<dots> = add a Infinity p\<^sub>3" by (simp add: add_0_l)
  also from p\<^sub>2 have "\<dots> = add a (add a p\<^sub>2 (opp p\<^sub>2)) p\<^sub>3"
    by (simp add: add_opp)
  also from a b p\<^sub>2 have "\<dots> = add a (add a (opp p\<^sub>2) p\<^sub>2) p\<^sub>3"
    by (simp add: add_comm opp_closed)
  finally show ?thesis using `p\<^sub>1 = opp p\<^sub>2` by simp
next
  assume "p\<^sub>2 = opp p\<^sub>3"
  from a b p\<^sub>3
  have "add a p\<^sub>1 (add a (opp p\<^sub>3) p\<^sub>3) = add a p\<^sub>1 (add a p\<^sub>3 (opp p\<^sub>3))"
    by (simp add: add_comm opp_closed)
  also from a b ab p\<^sub>1 p\<^sub>3
  have "\<dots> = add a (add a p\<^sub>1 (opp p\<^sub>3)) (opp (opp p\<^sub>3))"
    by (simp add: add_opp add_minus_id add_0_r opp_closed)
  finally show ?thesis using p\<^sub>3 `p\<^sub>2 = opp p\<^sub>3`
    by (simp add: opp_opp)
next
  assume eq: "opp p\<^sub>1 = add a p\<^sub>2 p\<^sub>3"
  from eq [symmetric] p\<^sub>1
  have "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = Infinity" by (simp add: add_opp)
  also from p\<^sub>3 have "\<dots> = add a p\<^sub>3 (opp p\<^sub>3)" by (simp add: add_opp)
  also from a b p\<^sub>3 have "\<dots> = add a (opp p\<^sub>3) p\<^sub>3"
    by (simp add: add_comm opp_closed)
  also from a b ab p\<^sub>2 p\<^sub>3
  have "\<dots> = add a (add a (add a (opp p\<^sub>3) (opp p\<^sub>2)) (opp (opp p\<^sub>2))) p\<^sub>3"
    by (simp add: add_minus_id opp_closed)
  also from a b p\<^sub>2 p\<^sub>3
  have "\<dots> = add a (add a (add a (opp p\<^sub>2) (opp p\<^sub>3)) p\<^sub>2) p\<^sub>3"
    by (simp add: add_comm opp_opp opp_closed)
  finally show ?thesis
    using opp_add [OF a b p\<^sub>2 p\<^sub>3] eq [symmetric] p\<^sub>1
    by (simp add: opp_opp)
next
  assume eq: "opp p\<^sub>3 = add a p\<^sub>1 p\<^sub>2"
  from opp_add [OF a b p\<^sub>1 p\<^sub>2] eq [symmetric] p\<^sub>3
  have "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a p\<^sub>1 (add a p\<^sub>2 (add a (opp p\<^sub>1) (opp p\<^sub>2)))"
    by (simp add: opp_opp)
  also from a b p\<^sub>1 p\<^sub>2
  have "\<dots> = add a p\<^sub>1 (add a (add a (opp p\<^sub>1) (opp p\<^sub>2)) (opp (opp p\<^sub>2)))"
    by (simp add: add_comm opp_opp add_closed opp_closed)
  also from a b ab p\<^sub>1 p\<^sub>2 have "\<dots> = Infinity"
    by (simp add: add_minus_id add_opp opp_closed)
  also from p\<^sub>3 have "\<dots> = add a p\<^sub>3 (opp p\<^sub>3)" by (simp add: add_opp)
  also from a b p\<^sub>3 have "\<dots> = add a (opp p\<^sub>3) p\<^sub>3"
    by (simp add: add_comm opp_closed)
  finally show ?thesis using eq [symmetric] by simp
qed

lemma spec4_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>2) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>2"
proof (cases "p\<^sub>1 = Infinity")
  case True
  from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
  show ?thesis by (rule degen_assoc) (simp add: True)
next
  case False
  show ?thesis
  proof (cases "p\<^sub>2 = Infinity")
    case True
    from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
    show ?thesis by (rule degen_assoc) (simp add: True)
  next
    case False
    show ?thesis
    proof (cases "p\<^sub>2 = opp p\<^sub>2")
      case True
      from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
      show ?thesis by (rule degen_assoc) (simp add: True [symmetric])
    next
      case False
      show ?thesis
      proof (cases "p\<^sub>1 = opp p\<^sub>2")
        case True
        from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
        show ?thesis by (rule degen_assoc) (simp add: True)
      next
        case False
        show ?thesis
        proof (cases "opp p\<^sub>1 = add a p\<^sub>2 p\<^sub>2")
          case True
          from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
          show ?thesis by (rule degen_assoc) (simp add: True)
        next
          case False
          show ?thesis
          proof (cases "opp p\<^sub>2 = add a p\<^sub>1 p\<^sub>2")
            case True
            from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>2
            show ?thesis by (rule degen_assoc) (simp add: True)
          next
            case False
            show ?thesis
            proof (cases "p\<^sub>1 = add a p\<^sub>2 p\<^sub>2")
              case True
              from a b p\<^sub>1 p\<^sub>2 `p\<^sub>1 \<noteq> opp p\<^sub>2` `p\<^sub>2 \<noteq> opp p\<^sub>2`
                `opp p\<^sub>1 \<noteq> add a p\<^sub>2 p\<^sub>2` `opp p\<^sub>2 \<noteq> add a p\<^sub>1 p\<^sub>2`
                `p\<^sub>1 \<noteq> Infinity` `p\<^sub>2 \<noteq> Infinity`
              show ?thesis
                apply (simp add: True)
                apply (rule spec3_assoc [OF a b])
                apply (simp_all add: is_generic_def is_tangent_def)
                apply (rule notI)
                apply (drule uniq_zero [OF a b ab p\<^sub>2 p\<^sub>2])
                apply simp
                apply (intro conjI notI)
                apply (erule notE)
                apply (rule uniq_opp [of a b])
                apply (simp_all add: add_comm add_closed)[2]
                apply (erule notE)
                apply (drule uniq_zero [OF a b ab add_closed [OF a b p\<^sub>2 p\<^sub>2] p\<^sub>2])
                apply simp
                done
            next
              case False
              show ?thesis
              proof (cases "p\<^sub>2 = add a p\<^sub>1 p\<^sub>2")
                case True
                from a b ab p\<^sub>1 p\<^sub>2 True [symmetric]
                have "p\<^sub>1 = Infinity" by (rule uniq_zero)
                then show ?thesis by (simp add: add_0_l)
              next
                case False
                show ?thesis
                proof (cases "p\<^sub>1 = p\<^sub>2")
                  case True
                  with a b p\<^sub>2 show ?thesis
                    by (simp add: add_comm add_closed)
                next
                  case False
                  with a b p\<^sub>1 p\<^sub>2 `p\<^sub>1 \<noteq> Infinity` `p\<^sub>2 \<noteq> Infinity`
                    `p\<^sub>1 \<noteq> opp p\<^sub>2` `p\<^sub>2 \<noteq> opp p\<^sub>2`
                    `p\<^sub>1 \<noteq> add a p\<^sub>2 p\<^sub>2` `p\<^sub>2 \<noteq> add a p\<^sub>1 p\<^sub>2` `opp p\<^sub>2 \<noteq> add a p\<^sub>1 p\<^sub>2`
                  show ?thesis
                    apply (rule_tac spec2_assoc [OF a b])
                    apply (simp_all add: is_generic_def is_tangent_def)
                    apply (rule notI)
                    apply (erule notE [of "p\<^sub>1 = opp p\<^sub>2"])
                    apply (rule uniq_opp)
                    apply assumption
                    apply (simp add: add_comm)
                    apply (intro conjI notI)
                    apply (erule notE [of "p\<^sub>2 = opp p\<^sub>2"])
                    apply (rule uniq_opp)
                    apply assumption+
                    apply (rule notE [OF `opp p\<^sub>1 \<noteq> add a p\<^sub>2 p\<^sub>2`])
                    apply (simp add: opp_opp [OF add_closed [OF a b p\<^sub>2 p\<^sub>2]])
                    done
                qed
              qed
            qed
          qed
        qed
      qed
    qed
  qed
qed

lemma add_assoc:
  assumes a: "a \<in> carrier R"
  and b: "b \<in> carrier R"
  and ab: "nonsingular a b"
  and p\<^sub>1: "on_curve a b p\<^sub>1"
  and p\<^sub>2: "on_curve a b p\<^sub>2"
  and p\<^sub>3: "on_curve a b p\<^sub>3"
  shows "add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>1 p\<^sub>2) p\<^sub>3"
proof (cases "p\<^sub>1 = Infinity")
  case True
  from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
  show ?thesis by (rule degen_assoc) (simp add: True)
next
  case False
  show ?thesis
  proof (cases "p\<^sub>2 = Infinity")
    case True
    from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
    show ?thesis by (rule degen_assoc) (simp add: True)
  next
    case False
    show ?thesis
    proof (cases "p\<^sub>3 = Infinity")
      case True
      from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
      show ?thesis by (rule degen_assoc) (simp add: True)
    next
      case False
      show ?thesis
      proof (cases "p\<^sub>1 = p\<^sub>2")
        case True
        from a b p\<^sub>2 p\<^sub>3
        have "add a p\<^sub>2 (add a p\<^sub>2 p\<^sub>3) = add a (add a p\<^sub>3 p\<^sub>2) p\<^sub>2"
          by (simp add: add_comm add_closed)
        also from a b ab p\<^sub>3 p\<^sub>2 have "\<dots> = add a p\<^sub>3 (add a p\<^sub>2 p\<^sub>2)"
          by (simp add: spec4_assoc)
        also from a b p\<^sub>2 p\<^sub>3
        have "\<dots> = add a (add a p\<^sub>2 p\<^sub>2) p\<^sub>3"
          by (simp add: add_comm add_closed)
        finally show ?thesis using True by simp
      next
        case False
        show ?thesis
        proof (cases "p\<^sub>1 = opp p\<^sub>2")
          case True
          from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
          show ?thesis by (rule degen_assoc) (simp add: True)
        next
          case False
          show ?thesis
          proof (cases "p\<^sub>2 = p\<^sub>3")
            case True
            with a b ab p\<^sub>1 p\<^sub>3 show ?thesis
              by (simp add: spec4_assoc)
          next
            case False
            show ?thesis
            proof (cases "p\<^sub>2 = opp p\<^sub>3")
              case True
              from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
              show ?thesis by (rule degen_assoc) (simp add: True)
            next
              case False
              show ?thesis
              proof (cases "opp p\<^sub>1 = add a p\<^sub>2 p\<^sub>3")
                case True
                from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
                show ?thesis by (rule degen_assoc) (simp add: True)
              next
                case False
                show ?thesis
                proof (cases "opp p\<^sub>3 = add a p\<^sub>1 p\<^sub>2")
                  case True
                  from a b ab p\<^sub>1 p\<^sub>2 p\<^sub>3
                  show ?thesis by (rule degen_assoc) (simp add: True)
                next
                  case False
                  show ?thesis
                  proof (cases "p\<^sub>1 = add a p\<^sub>2 p\<^sub>3")
                    case True
                    with a b ab p\<^sub>2 p\<^sub>3 show ?thesis
                      apply simp
                      apply (rule cancel [OF a b ab opp_closed [OF p\<^sub>3]])
                      apply (simp_all add: add_closed)
                      apply (simp add: spec4_assoc add_closed opp_closed)
                      apply (simp add: add_comm [of a b "opp p\<^sub>3"]
                        add_closed opp_closed add_minus_id)
                      apply (simp add: add_comm add_closed)
                      done
                  next
                    case False
                    show ?thesis
                    proof (cases "p\<^sub>3 = add a p\<^sub>1 p\<^sub>2")
                      case True
                      with a b ab p\<^sub>1 p\<^sub>2 show ?thesis
                        apply simp
                        apply (rule cancel [OF a b ab opp_closed [OF p\<^sub>1]])
                        apply (simp_all add: add_closed)
                        apply (simp add: spec4_assoc add_closed opp_closed)
                        apply (simp add: add_comm [of a b "opp p\<^sub>1"] add_comm [of a b p\<^sub>1]
                          add_closed opp_closed add_minus_id)
                        done
                    next
                      case False
                      with a b p\<^sub>1 p\<^sub>2 p\<^sub>3
                        `p\<^sub>1 \<noteq> Infinity` `p\<^sub>2 \<noteq> Infinity` `p\<^sub>3 \<noteq> Infinity`
                        `p\<^sub>1 \<noteq> p\<^sub>2` `p\<^sub>1 \<noteq> opp p\<^sub>2` `p\<^sub>2 \<noteq> p\<^sub>3` `p\<^sub>2 \<noteq> opp p\<^sub>3`
                        `opp p\<^sub>3 \<noteq> add a p\<^sub>1 p\<^sub>2` `p\<^sub>1 \<noteq> add a p\<^sub>2 p\<^sub>3`
                      show ?thesis
                        apply (rule_tac spec1_assoc [of a b])
                        apply (simp_all add: is_generic_def)
                        apply (rule notI)
                        apply (erule notE [of "p\<^sub>1 = opp p\<^sub>2"])
                        apply (rule uniq_opp)
                        apply assumption
                        apply (simp add: add_comm)
                        apply (intro conjI notI)
                        apply (erule notE [of "p\<^sub>2 = opp p\<^sub>3"])
                        apply (rule uniq_opp)
                        apply assumption
                        apply (simp add: add_comm)
                        apply (rule notE [OF `opp p\<^sub>1 \<noteq> add a p\<^sub>2 p\<^sub>3`])
                        apply (simp add: opp_opp [OF add_closed [OF a b p\<^sub>2 p\<^sub>3]])
                        done
                    qed
                  qed
                qed
              qed
            qed
          qed
        qed
      qed
    qed
  qed
qed

lemma add_comm':
  "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> nonsingular a b \<Longrightarrow>
   on_curve a b p\<^sub>1 \<Longrightarrow> on_curve a b p\<^sub>2 \<Longrightarrow> on_curve a b p\<^sub>3 \<Longrightarrow>
   add a p\<^sub>2 (add a p\<^sub>1 p\<^sub>3) = add a p\<^sub>1 (add a p\<^sub>2 p\<^sub>3)"
   by (simp add: add_assoc add_comm)

primrec point_mult :: "'a \<Rightarrow> nat \<Rightarrow> 'a point \<Rightarrow> 'a point"
where
    "point_mult a 0 p = Infinity"
  | "point_mult a (Suc n) p = add a p (point_mult a n p)"

lemma point_mult_closed: "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow>
  on_curve a b p \<Longrightarrow> on_curve a b (point_mult a n p)"
  by (induct n) (simp_all add: add_closed)

lemma point_mult_add:
  "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> on_curve a b p \<Longrightarrow> nonsingular a b \<Longrightarrow>
   point_mult a (m + n) p = add a (point_mult a m p) (point_mult a n p)"
  by (induct m) (simp_all add: add_assoc point_mult_closed add_0_l)

lemma point_mult_mult:
  "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> on_curve a b p \<Longrightarrow> nonsingular a b \<Longrightarrow>
   point_mult a (m * n) p = point_mult a n (point_mult a m p)"
   by (induct n) (simp_all add: point_mult_add)

lemma point_mult2_eq_double:
  "point_mult a 2 p = add a p p"
  by (simp add: numeral_2_eq_2 add_0_r)

end

type_synonym 'a ppoint = "'a \<times> 'a \<times> 'a"

definition (in cring) pdouble :: "'a \<Rightarrow> 'a ppoint \<Rightarrow> 'a ppoint" where
  "pdouble a p =
     (let (x, y, z) = p
      in
        if z = \<zero> then p
        else
          let
            l = \<guillemotleft>2\<guillemotright> \<otimes> y \<otimes> z;
            m = \<guillemotleft>3\<guillemotright> \<otimes> x (^) (2::nat) \<oplus> a \<otimes> z (^) (2::nat)
          in
            (l \<otimes> (m (^) (2::nat) \<ominus> \<guillemotleft>4\<guillemotright> \<otimes> x \<otimes> y \<otimes> l),
             m \<otimes> (\<guillemotleft>6\<guillemotright> \<otimes> x \<otimes> y \<otimes> l \<ominus> m (^) (2::nat)) \<ominus>
             \<guillemotleft>2\<guillemotright> \<otimes> y (^) (2::nat) \<otimes> l (^) (2::nat),
             l (^) (3::nat)))"

definition (in cring) padd :: "'a \<Rightarrow> 'a ppoint \<Rightarrow> 'a ppoint \<Rightarrow> 'a ppoint" where
  "padd a p\<^sub>1 p\<^sub>2 =
     (let
        (x\<^sub>1, y\<^sub>1, z\<^sub>1) = p\<^sub>1;
        (x\<^sub>2, y\<^sub>2, z\<^sub>2) = p\<^sub>2
      in
        if z\<^sub>1 = \<zero> then p\<^sub>2
        else if z\<^sub>2 = \<zero> then p\<^sub>1
        else
          let
            d\<^sub>1 = x\<^sub>2 \<otimes> z\<^sub>1;
            d\<^sub>2 = x\<^sub>1 \<otimes> z\<^sub>2;
            l = d\<^sub>1 \<ominus> d\<^sub>2;
            m = y\<^sub>2 \<otimes> z\<^sub>1 \<ominus> y\<^sub>1 \<otimes> z\<^sub>2
          in
            if l = \<zero> then
              if m = \<zero> then pdouble a p\<^sub>1
              else (\<zero>, \<zero>, \<zero>)
            else
              let h = m (^) (2::nat) \<otimes> z\<^sub>1 \<otimes> z\<^sub>2 \<ominus> (d\<^sub>1 \<oplus> d\<^sub>2) \<otimes> l (^) (2::nat)
              in
                (l \<otimes> h,
                 (d\<^sub>2 \<otimes> l (^) (2::nat) \<ominus> h) \<otimes> m \<ominus> l (^) (3::nat) \<otimes> y\<^sub>1 \<otimes> z\<^sub>2,
                 l (^) (3::nat) \<otimes> z\<^sub>1 \<otimes> z\<^sub>2))"

definition (in field) make_affine :: "'a ppoint \<Rightarrow> 'a point" where
  "make_affine p =
     (let (x, y, z) = p
      in if z = \<zero> then Infinity else Point (x \<oslash> z) (y \<oslash> z))"

definition (in cring) in_carrierp :: "'a ppoint \<Rightarrow> bool" where
  "in_carrierp = (\<lambda>(x, y, z). x \<in> carrier R \<and> y \<in> carrier R \<and> z \<in> carrier R)"

definition (in cring) on_curvep :: "'a \<Rightarrow> 'a \<Rightarrow> 'a ppoint \<Rightarrow> bool" where
  "on_curvep a b = (\<lambda>(x, y, z).
     x \<in> carrier R \<and> y \<in> carrier R \<and> z \<in> carrier R \<and>
     (z \<noteq> \<zero> \<longrightarrow>
      y (^) (2::nat) \<otimes> z = x (^) (3::nat) \<oplus> a \<otimes> x \<otimes> z (^) (2::nat) \<oplus> b \<otimes> z (^) (3::nat)))"

lemma (in cring) on_curvep_infinity [simp]: "on_curvep a b (x, y, \<zero>) = (x \<in> carrier R \<and> y \<in> carrier R)"
  by (simp add: on_curvep_def)

lemma (in field) make_affine_infinity [simp]: "make_affine (x, y, \<zero>) = Infinity"
  by (simp add: make_affine_def)

lemma (in cring) on_curvep_imp_in_carrierp [simp]: "on_curvep a b p \<Longrightarrow> in_carrierp p"
  by (auto simp add: on_curvep_def in_carrierp_def)

lemma (in ell_field) on_curvep_iff_on_curve:
  assumes "a \<in> carrier R" "b \<in> carrier R" "in_carrierp p"
  shows "on_curvep a b p = on_curve a b (make_affine p)"
  using assms
proof (induct p rule: prod_induct3)
  case (fields x y z)
  show "on_curvep a b (x, y, z) = on_curve a b (make_affine (x, y, z))"
  proof
    assume H: "on_curvep a b (x, y, z)"
    then have carrier: "x \<in> carrier R" "y \<in> carrier R" "z \<in> carrier R"
      and yz: "z \<noteq> \<zero> \<Longrightarrow>
        y (^) (2::nat) \<otimes> z = x (^) (3::nat) \<oplus> a \<otimes> x \<otimes> z (^) (2::nat) \<oplus> b \<otimes> z (^) (3::nat)"
      by (simp_all add: on_curvep_def)
    show "on_curve a b (make_affine (x, y, z))"
    proof (cases "z = \<zero>")
      case True
      then show ?thesis by (simp add: on_curve_def make_affine_def)
    next
      case False
      then show ?thesis
        apply (simp add: on_curve_def make_affine_def carrier)
        apply (field yz [OF False])
        apply assumption
        done
    qed
  next
    assume H: "on_curve a b (make_affine (x, y, z))"
    show "on_curvep a b (x, y, z)"
    proof (cases "z = \<zero>")
      case True
      with `in_carrierp (x, y, z)` show ?thesis
        by (simp add: on_curvep_def in_carrierp_def)
    next
      case False
      from `in_carrierp (x, y, z)`
      have carrier: "x \<in> carrier R" "y \<in> carrier R" "z \<in> carrier R"
        by (simp_all add: in_carrierp_def)
      from H show ?thesis
        apply (simp add: on_curve_def on_curvep_def make_affine_def carrier False)
        apply (field (prems))
        apply field
        apply (simp_all add: False)
        done
    qed
  qed
qed

lemma (in cring) pdouble_in_carrierp:
  "a \<in> carrier R \<Longrightarrow> in_carrierp p \<Longrightarrow> in_carrierp (pdouble a p)"
  by (auto simp add: in_carrierp_def pdouble_def Let_def split add: prod.split)

lemma (in cring) padd_in_carrierp:
  "a \<in> carrier R \<Longrightarrow> in_carrierp p\<^sub>1 \<Longrightarrow> in_carrierp p\<^sub>2 \<Longrightarrow> in_carrierp (padd a p\<^sub>1 p\<^sub>2)"
  by (auto simp add: padd_def Let_def pdouble_in_carrierp split add: prod.split)
    (auto simp add: in_carrierp_def)

lemma (in cring) pdouble_infinity [simp]: "pdouble a (x, y, \<zero>) = (x, y, \<zero>)"
  by (simp add: pdouble_def)

lemma (in cring) padd_infinity_l [simp]: "padd a (x, y, \<zero>) p = p"
  by (simp add: padd_def)

lemma (in ell_field) pdouble_correct:
  "a \<in> carrier R \<Longrightarrow> in_carrierp p \<Longrightarrow>
   make_affine (pdouble a p) = add a (make_affine p) (make_affine p)"
proof (induct p rule: prod_induct3)
  case (fields x y z)
  then have "x \<in> carrier R" "y \<in> carrier R" "z \<in> carrier R"
    by (simp_all add: in_carrierp_def)
  then show ?case
    apply (auto simp add: add_def pdouble_def make_affine_def equal_neg_zero divide_eq_0_iff
      integral_iff Let_def simp del: minus_divide_left)
    apply field
    apply (simp add: integral_iff)
    apply field
    apply (simp add: integral_iff)
    done
qed

lemma (in ell_field) padd_correct:
  assumes a: "a \<in> carrier R" and b: "b \<in> carrier R"
  and p\<^sub>1: "on_curvep a b p\<^sub>1" and p\<^sub>2: "on_curvep a b p\<^sub>2"
  shows "make_affine (padd a p\<^sub>1 p\<^sub>2) = add a (make_affine p\<^sub>1) (make_affine p\<^sub>2)"
  using p\<^sub>1
proof (induct p\<^sub>1 rule: prod_induct3)
  case (fields x\<^sub>1 y\<^sub>1 z\<^sub>1)
  note p\<^sub>1' = fields
  from p\<^sub>2 show ?case
  proof (induct p\<^sub>2 rule: prod_induct3)
    case (fields x\<^sub>2 y\<^sub>2 z\<^sub>2)
    then have "x\<^sub>2 \<in> carrier R" "y\<^sub>2 \<in> carrier R" "z\<^sub>2 \<in> carrier R" and
      yz\<^sub>2: "z\<^sub>2 \<noteq> \<zero> \<Longrightarrow> y\<^sub>2 (^) (2::nat) \<otimes> z\<^sub>2 \<otimes> z\<^sub>1 (^) (3::nat) =
        (x\<^sub>2 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>2 \<otimes> z\<^sub>2 (^) (2::nat) \<oplus> b \<otimes> z\<^sub>2 (^) (3::nat)) \<otimes> z\<^sub>1 (^) (3::nat)"
      by (simp_all add: on_curvep_def)
    from p\<^sub>1' have "x\<^sub>1 \<in> carrier R" "y\<^sub>1 \<in> carrier R" "z\<^sub>1 \<in> carrier R" and
      yz\<^sub>1: "z\<^sub>1 \<noteq> \<zero> \<Longrightarrow> y\<^sub>1 (^) (2::nat) \<otimes> z\<^sub>1 \<otimes> z\<^sub>2 (^) (3::nat) =
        (x\<^sub>1 (^) (3::nat) \<oplus> a \<otimes> x\<^sub>1 \<otimes> z\<^sub>1 (^) (2::nat) \<oplus> b \<otimes> z\<^sub>1 (^) (3::nat)) \<otimes> z\<^sub>2 (^) (3::nat)"
      by (simp_all add: on_curvep_def)
    show ?case
    proof (cases "z\<^sub>1 = \<zero>")
      case True
      then show ?thesis
        by (simp add: add_def padd_def make_affine_def)
    next
      case False
      show ?thesis
      proof (cases "z\<^sub>2 = \<zero>")
        case True
        then show ?thesis
          by (simp add: add_def padd_def make_affine_def)
      next
        case False
        show ?thesis
        proof (cases "x\<^sub>2 \<otimes> z\<^sub>1 \<ominus> x\<^sub>1 \<otimes> z\<^sub>2 = \<zero>")
          case True
          note x = this
          with `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `z\<^sub>1 \<in> carrier R` ` z\<^sub>2 \<in> carrier R`
          have x': "x\<^sub>2 \<otimes> z\<^sub>1 = x\<^sub>1 \<otimes> z\<^sub>2" by (simp add: eq_diff0)
          show ?thesis
          proof (cases "y\<^sub>2 \<otimes> z\<^sub>1 \<ominus> y\<^sub>1 \<otimes> z\<^sub>2 = \<zero>")
            case True
            with `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R` `z\<^sub>1 \<in> carrier R` ` z\<^sub>2 \<in> carrier R`
            have y: "y\<^sub>2 \<otimes> z\<^sub>1 = y\<^sub>1 \<otimes> z\<^sub>2" by (simp add: eq_diff0)
            from `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>` x
            have "make_affine (x\<^sub>2, y\<^sub>2, z\<^sub>2) = make_affine (x\<^sub>1, y\<^sub>1, z\<^sub>1)"
              apply (simp add: make_affine_def)
              apply (rule conjI)
              apply (field x')
              apply simp
              apply (field y)
              apply simp
              done
            with True x `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>` p\<^sub>1' fields a show ?thesis
              by (simp add: padd_def pdouble_correct)
          next
            case False
            have "y\<^sub>2 (^) (2::nat) \<otimes> z\<^sub>1 (^) (3::nat) \<otimes> z\<^sub>2 =
              y\<^sub>1 (^) (2::nat) \<otimes> z\<^sub>1 \<otimes> z\<^sub>2 (^) (3::nat)"
              by (ring yz\<^sub>1 [OF `z\<^sub>1 \<noteq> \<zero>`] yz\<^sub>2 [OF `z\<^sub>2 \<noteq> \<zero>`] x')
            then have "y\<^sub>2 (^) (2::nat) \<otimes> z\<^sub>1 (^) (3::nat) \<otimes> z\<^sub>2 \<oslash> z\<^sub>1 \<oslash> z\<^sub>2 =
              y\<^sub>1 (^) (2::nat) \<otimes> z\<^sub>1 \<otimes> z\<^sub>2 (^) (3::nat) \<oslash> z\<^sub>1 \<oslash> z\<^sub>2"
              by simp
            then have "(y\<^sub>2 \<otimes> z\<^sub>1) \<otimes> (y\<^sub>2 \<otimes> z\<^sub>1) = (y\<^sub>1 \<otimes> z\<^sub>2) \<otimes> (y\<^sub>1 \<otimes> z\<^sub>2)"
              apply (field (prems))
              apply (field)
              apply (rule TrueI)
              apply (simp add: `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>`)
              done
            with False
            have y\<^sub>2z\<^sub>1: "y\<^sub>2 \<otimes> z\<^sub>1 = \<ominus> (y\<^sub>1 \<otimes> z\<^sub>2)"
              by (simp add: square_eq_iff eq_diff0
                `y\<^sub>1 \<in> carrier R` `y\<^sub>2 \<in> carrier R` `z\<^sub>1 \<in> carrier R` `z\<^sub>2 \<in> carrier R`)
            from x False `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>` show ?thesis
              apply (simp add: padd_def add_def make_affine_def Let_def)
              apply (rule conjI)
              apply (rule impI)
              apply (field x')
              apply simp
              apply (field y\<^sub>2z\<^sub>1)
              apply simp
              done
          qed
        next
          case False
          then have "x\<^sub>1 \<oslash> z\<^sub>1 \<noteq> x\<^sub>2 \<oslash> z\<^sub>2"
            apply (rule_tac notI)
            apply (erule notE)
            apply (drule sym)
            apply (field (prems))
            apply ring
            apply (simp add: `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>`)
            done
          with False `z\<^sub>1 \<noteq> \<zero>` `z\<^sub>2 \<noteq> \<zero>`
            `x\<^sub>1 \<in> carrier R` `x\<^sub>2 \<in> carrier R` `z\<^sub>1 \<in> carrier R` `z\<^sub>2 \<in> carrier R`
          show ?thesis
            apply (auto simp add: padd_def add_def make_affine_def Let_def integral_iff)
            apply field
            apply (simp add: integral_iff)
            apply field
            apply (simp add: integral_iff)
            done
        qed
      qed
    qed
  qed
qed

lemma (in ell_field) pdouble_closed:
  assumes "a \<in> carrier R" "b \<in> carrier R" "on_curvep a b p"
  shows "on_curvep a b (pdouble a p)"
proof -
  from `on_curvep a b p` have "in_carrierp p" by simp
  from assms show ?thesis
    by (simp add: on_curvep_iff_on_curve pdouble_in_carrierp pdouble_correct
      add_closed `in_carrierp p`)
qed

lemma (in ell_field) padd_closed:
  assumes "a \<in> carrier R" "b \<in> carrier R" "on_curvep a b p\<^sub>1" "on_curvep a b p\<^sub>2"
  shows "on_curvep a b (padd a p\<^sub>1 p\<^sub>2)"
proof -
  from `on_curvep a b p\<^sub>1` have "in_carrierp p\<^sub>1" by simp
  from `on_curvep a b p\<^sub>2` have "in_carrierp p\<^sub>2" by simp
  from assms show ?thesis
    by (simp add: on_curvep_iff_on_curve padd_in_carrierp padd_correct
      add_closed `in_carrierp p\<^sub>1` `in_carrierp p\<^sub>2`)
qed

primrec (in cring) ppoint_mult :: "'a \<Rightarrow> nat \<Rightarrow> 'a ppoint \<Rightarrow> 'a ppoint"
where
    "ppoint_mult a 0 p = (\<zero>, \<zero>, \<zero>)"
  | "ppoint_mult a (Suc n) p = padd a p (ppoint_mult a n p)"

lemma (in ell_field) ppoint_mult_closed [simp]:
  "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> on_curvep a b p \<Longrightarrow> on_curvep a b (ppoint_mult a n p)"
  by (induct n) (simp_all add: padd_closed)

lemma (in ell_field) ppoint_mult_correct: "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> on_curvep a b p \<Longrightarrow>
  make_affine (ppoint_mult a n p) = point_mult a n (make_affine p)"
  by (induct n) (simp_all add: padd_correct)

definition (in cring) proj_eq :: "'a ppoint \<Rightarrow> 'a ppoint \<Rightarrow> bool" where
  "proj_eq = (\<lambda>(x\<^sub>1, y\<^sub>1, z\<^sub>1) (x\<^sub>2, y\<^sub>2, z\<^sub>2).
     (z\<^sub>1 = \<zero>) = (z\<^sub>2 = \<zero>) \<and> x\<^sub>1 \<otimes> z\<^sub>2 = x\<^sub>2 \<otimes> z\<^sub>1 \<and> y\<^sub>1 \<otimes> z\<^sub>2 = y\<^sub>2 \<otimes> z\<^sub>1)"

lemma (in cring) proj_eq_refl: "proj_eq p p"
  by (auto simp add: proj_eq_def)

lemma (in cring) proj_eq_sym: "proj_eq p p' \<Longrightarrow> proj_eq p' p"
  by (auto simp add: proj_eq_def)

lemma (in domain) proj_eq_trans:
  "in_carrierp p \<Longrightarrow> in_carrierp p' \<Longrightarrow> in_carrierp p'' \<Longrightarrow>
   proj_eq p p' \<Longrightarrow> proj_eq p' p'' \<Longrightarrow> proj_eq p p''"
proof (induct p rule: prod_induct3)
  case (fields x y z)
  then show ?case
  proof (induct p' rule: prod_induct3)
    case (fields x' y' z')
    then show ?case
    proof (induct p'' rule: prod_induct3)
      case (fields x'' y'' z'')
      then have carrier:
        "x \<in> carrier R" "y \<in> carrier R" "z \<in> carrier R"
        "x' \<in> carrier R" "y' \<in> carrier R" "z' \<in> carrier R"
        "x'' \<in> carrier R" "y'' \<in> carrier R" "z'' \<in> carrier R"
        and z: "(z = \<zero>) = (z' = \<zero>)" "(z' = \<zero>) = (z'' = \<zero>)" and
        "x \<otimes> z' \<otimes> z'' = x' \<otimes> z \<otimes> z''"
        "y \<otimes> z' \<otimes> z'' = y' \<otimes> z \<otimes> z''"
        and xy:
        "x' \<otimes> z'' = x'' \<otimes> z'"
        "y' \<otimes> z'' = y'' \<otimes> z'"
        by (simp_all add: in_carrierp_def proj_eq_def)
      from `x \<otimes> z' \<otimes> z'' = x' \<otimes> z \<otimes> z''`
      have "(x \<otimes> z'') \<otimes> z' = (x'' \<otimes> z) \<otimes> z'"
        by (ring (prems) xy) (ring xy)
      moreover from `y \<otimes> z' \<otimes> z'' = y' \<otimes> z \<otimes> z''`
      have "(y \<otimes> z'') \<otimes> z' = (y'' \<otimes> z) \<otimes> z'"
        by (ring (prems) xy) (ring xy)
      ultimately show ?case using z
        by (auto simp add: proj_eq_def carrier conc)
    qed
  qed
qed

lemma (in field) make_affine_proj_eq_iff:
  "in_carrierp p \<Longrightarrow> in_carrierp p' \<Longrightarrow> proj_eq p p' = (make_affine p = make_affine p')"
proof (induct p rule: prod_induct3)
  case (fields x y z)
  then show ?case
  proof (induct p' rule: prod_induct3)
    case (fields x' y' z')
    then have carrier:
      "x \<in> carrier R" "y \<in> carrier R" "z \<in> carrier R"
      "x' \<in> carrier R" "y' \<in> carrier R" "z' \<in> carrier R"
      by (simp_all add: in_carrierp_def)
    show ?case
    proof
      assume "proj_eq (x, y, z) (x', y', z')"
      then have "(z = \<zero>) = (z' = \<zero>)"
        and xy: "x \<otimes> z' = x' \<otimes> z" "y \<otimes> z' = y' \<otimes> z"
        by (simp_all add: proj_eq_def)
      then show "make_affine (x, y, z) = make_affine (x', y', z')"
        apply (auto simp add: make_affine_def)
        apply (field xy)
        apply simp
        apply (field xy)
        apply simp
        done
    next
      assume H: "make_affine (x, y, z) = make_affine (x', y', z')"
      show "proj_eq (x, y, z) (x', y', z')"
      proof (cases "z = \<zero>")
        case True
        with H have "z' = \<zero>" by (simp add: make_affine_def split add: split_if_asm)
        with True carrier show ?thesis by (simp add: proj_eq_def)
      next
        case False
        with H have "z' \<noteq> \<zero>" "x \<oslash> z = x' \<oslash> z'" "y \<oslash> z = y' \<oslash> z'"
          by (simp_all add: make_affine_def split add: split_if_asm)
        from `x \<oslash> z = x' \<oslash> z'`
        have "x \<otimes> z' = x' \<otimes> z"
          apply (field (prems))
          apply field
          apply (simp_all add: `z \<noteq> \<zero>` `z' \<noteq> \<zero>`)
          done
        moreover from `y \<oslash> z = y' \<oslash> z'`
        have "y \<otimes> z' = y' \<otimes> z"
          apply (field (prems))
          apply field
          apply (simp_all add: `z \<noteq> \<zero>` `z' \<noteq> \<zero>`)
          done
        ultimately show ?thesis
          by (simp add: proj_eq_def `z \<noteq> \<zero>` `z' \<noteq> \<zero>`)
      qed
    qed
  qed
qed

lemma (in ell_field) pdouble_proj_eq_cong:
  "a \<in> carrier R \<Longrightarrow> in_carrierp p \<Longrightarrow> in_carrierp p' \<Longrightarrow> proj_eq p p' \<Longrightarrow>
   proj_eq (pdouble a p) (pdouble a p')"
  by (simp add: make_affine_proj_eq_iff pdouble_in_carrierp pdouble_correct)

lemma (in ell_field) padd_proj_eq_cong:
  "a \<in> carrier R \<Longrightarrow> b \<in> carrier R \<Longrightarrow> on_curvep a b p\<^sub>1 \<Longrightarrow> on_curvep a b p\<^sub>1' \<Longrightarrow>
   on_curvep a b p\<^sub>2 \<Longrightarrow> on_curvep a b p\<^sub>2' \<Longrightarrow> proj_eq p\<^sub>1 p\<^sub>1' \<Longrightarrow> proj_eq p\<^sub>2 p\<^sub>2' \<Longrightarrow>
   proj_eq (padd a p\<^sub>1 p\<^sub>2) (padd a p\<^sub>1' p\<^sub>2')"
  by (simp add: make_affine_proj_eq_iff padd_in_carrierp padd_correct)

end
