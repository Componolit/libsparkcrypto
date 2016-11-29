theory Reflective_Field
imports Commutative_Ring
begin

datatype fexpr =
    FCnst int
  | FVar nat
  | FAdd fexpr fexpr
  | FSub fexpr fexpr
  | FMul fexpr fexpr
  | FNeg fexpr
  | FDiv fexpr fexpr
  | FPow fexpr nat

fun (in field) nth_el :: "'a list \<Rightarrow> nat \<Rightarrow> 'a" where
  "nth_el [] n = \<zero>"
| "nth_el (x # xs) 0 = x"
| "nth_el (x # xs) (Suc n) = nth_el xs n"

lemma (in field) nth_el_Cons:
  "nth_el (x # xs) n = (if n = 0 then x else nth_el xs (n - 1))"
  by (cases n) simp_all

lemma (in field) nth_el_closed [simp]:
  "in_carrier xs \<Longrightarrow> nth_el xs n \<in> carrier R"
  by (induct xs n rule: nth_el.induct) (simp_all add: in_carrier_def)

primrec (in field) feval :: "'a list \<Rightarrow> fexpr \<Rightarrow> 'a"
where
  "feval xs (FCnst c) = \<guillemotleft>c\<guillemotright>"
| "feval xs (FVar n) = nth_el xs n"
| "feval xs (FAdd a b) = feval xs a \<oplus> feval xs b"
| "feval xs (FSub a b) = feval xs a \<ominus> feval xs b"
| "feval xs (FMul a b) = feval xs a \<otimes> feval xs b"
| "feval xs (FNeg a) = \<ominus> feval xs a"
| "feval xs (FDiv a b) = feval xs a \<oslash> feval xs b"
| "feval xs (FPow a n) = feval xs a (^) n"

lemma (in field) feval_Cnst:
  "feval xs (FCnst 0) = \<zero>"
  "feval xs (FCnst 1) = \<one>"
  "feval xs (FCnst (numeral n)) = \<guillemotleft>numeral n\<guillemotright>"
  by simp_all

datatype pexpr =
    PExpr1 pexpr1
  | PExpr2 pexpr2
and pexpr1 =
    PCnst int
  | PVar nat
  | PAdd pexpr pexpr
  | PSub pexpr pexpr
  | PNeg pexpr
and pexpr2 =
    PMul pexpr pexpr
  | PPow pexpr nat

lemma pexpr_cases [case_names PCnst PVar PAdd PSub PNeg PMul PPow]:
  assumes
    "\<And>c. e = PExpr1 (PCnst c) \<Longrightarrow> P"
    "\<And>n. e = PExpr1 (PVar n) \<Longrightarrow> P"
    "\<And>e1 e2. e = PExpr1 (PAdd e1 e2) \<Longrightarrow> P"
    "\<And>e1 e2. e = PExpr1 (PSub e1 e2) \<Longrightarrow> P"
    "\<And>e'. e = PExpr1 (PNeg e') \<Longrightarrow> P"
    "\<And>e1 e2. e = PExpr2 (PMul e1 e2) \<Longrightarrow> P"
    "\<And>e' n. e = PExpr2 (PPow e' n) \<Longrightarrow> P"
  shows P
proof (cases e)
  case (PExpr1 e')
  then show ?thesis
    apply (cases e')
    apply simp_all
    apply (erule assms)+
    done
next
  case (PExpr2 e')
  then show ?thesis
    apply (cases e')
    apply simp_all
    apply (erule assms)+
    done
qed

lemmas pexpr_cases2 = pexpr_cases [case_product pexpr_cases]

fun (in field) peval :: "'a list \<Rightarrow> pexpr \<Rightarrow> 'a"
where
  "peval xs (PExpr1 (PCnst c)) = \<guillemotleft>c\<guillemotright>"
| "peval xs (PExpr1 (PVar n)) = nth_el xs n"
| "peval xs (PExpr1 (PAdd a b)) = peval xs a \<oplus> peval xs b"
| "peval xs (PExpr1 (PSub a b)) = peval xs a \<ominus> peval xs b"
| "peval xs (PExpr1 (PNeg a)) = \<ominus> peval xs a"
| "peval xs (PExpr2 (PMul a b)) = peval xs a \<otimes> peval xs b"
| "peval xs (PExpr2 (PPow a n)) = peval xs a (^) n"

lemma (in field) peval_Cnst:
  "peval xs (PExpr1 (PCnst 0)) = \<zero>"
  "peval xs (PExpr1 (PCnst 1)) = \<one>"
  "peval xs (PExpr1 (PCnst (numeral n))) = \<guillemotleft>numeral n\<guillemotright>"
  "peval xs (PExpr1 (PCnst (- numeral n))) = \<ominus> \<guillemotleft>numeral n\<guillemotright>"
  by simp_all

lemma (in field) peval_closed [simp]:
  "in_carrier xs \<Longrightarrow> peval xs e \<in> carrier R"
  "in_carrier xs \<Longrightarrow> peval xs (PExpr1 e1) \<in> carrier R"
  "in_carrier xs \<Longrightarrow> peval xs (PExpr2 e2) \<in> carrier R"
  by (induct e and e1 and e2) simp_all

definition npepow :: "pexpr \<Rightarrow> nat \<Rightarrow> pexpr"
where
  "npepow e n =
     (if n = 0 then PExpr1 (PCnst 1)
      else if n = 1 then e
      else (case e of
          PExpr1 (PCnst c) \<Rightarrow> PExpr1 (PCnst (c ^ n))
        | _ \<Rightarrow> PExpr2 (PPow e n)))"

lemma (in field) npepow_correct:
  "in_carrier xs \<Longrightarrow> peval xs (npepow e n) = peval xs (PExpr2 (PPow e n))"
  by (cases e rule: pexpr_cases)
    (simp_all add: npepow_def)

fun npemul :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr"
where
  "npemul x y = (case x of
       PExpr1 (PCnst c) \<Rightarrow>
         if c = 0 then x
         else if c = 1 then y else
           (case y of
              PExpr1 (PCnst d) \<Rightarrow> PExpr1 (PCnst (c * d))
            | _ \<Rightarrow> PExpr2 (PMul x y))
     | PExpr2 (PPow e1 n) \<Rightarrow>
         (case y of
            PExpr2 (PPow e2 m) \<Rightarrow>
              if n = m then npepow (npemul e1 e2) n
              else PExpr2 (PMul x y)
          | PExpr1 (PCnst d) \<Rightarrow>
              if d = 0 then y
              else if d = 1 then x
              else PExpr2 (PMul x y)
          | _ \<Rightarrow> PExpr2 (PMul x y))
     | _ \<Rightarrow> (case y of
         PExpr1 (PCnst d) \<Rightarrow>
           if d = 0 then y
           else if d = 1 then x
           else PExpr2 (PMul x y)
       | _ \<Rightarrow> PExpr2 (PMul x y)))"

lemma (in field) npemul_correct:
  "in_carrier xs \<Longrightarrow> peval xs (npemul e1 e2) = peval xs (PExpr2 (PMul e1 e2))"
proof (induct e1 e2 rule: npemul.induct)
  case (1 x y)
  then show ?case
  proof (cases x y rule: pexpr_cases2)
    case (PPow_PPow e n e' m)
    then show ?thesis
    by (simp add: 1 npepow_correct nat_pow_distr
      npemul.simps [of "PExpr2 (PPow e n)" "PExpr2 (PPow e' m)"]
      del: npemul.simps)
  qed simp_all
qed

declare npemul.simps [simp del]

definition npeadd :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr"
where
  "npeadd x y = (case x of
       PExpr1 (PCnst c) \<Rightarrow>
         if c = 0 then y else
           (case y of
              PExpr1 (PCnst d) \<Rightarrow> PExpr1 (PCnst (c + d))
            | _ \<Rightarrow> PExpr1 (PAdd x y))
     | _ \<Rightarrow> (case y of
         PExpr1 (PCnst d) \<Rightarrow>
           if d = 0 then x
           else PExpr1 (PAdd x y)
       | _ \<Rightarrow> PExpr1 (PAdd x y)))"

lemma (in field) npeadd_correct:
  "in_carrier xs \<Longrightarrow> peval xs (npeadd e1 e2) = peval xs (PExpr1 (PAdd e1 e2))"
  by (cases e1 e2 rule: pexpr_cases2) (simp_all add: npeadd_def)

definition npesub :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr"
where
  "npesub x y = (case y of
       PExpr1 (PCnst d) \<Rightarrow>
         if d = 0 then x else
           (case x of
              PExpr1 (PCnst c) \<Rightarrow> PExpr1 (PCnst (c - d))
            | _ \<Rightarrow> PExpr1 (PSub x y))
     | _ \<Rightarrow> (case x of
         PExpr1 (PCnst c) \<Rightarrow>
           if c = 0 then PExpr1 (PNeg y)
           else PExpr1 (PSub x y)
       | _ \<Rightarrow> PExpr1 (PSub x y)))"

lemma (in field) npesub_correct:
  "in_carrier xs \<Longrightarrow> peval xs (npesub e1 e2) = peval xs (PExpr1 (PSub e1 e2))"
  by (cases e1 e2 rule: pexpr_cases2) (simp_all add: npesub_def)

definition npeneg :: "pexpr \<Rightarrow> pexpr"
where
  "npeneg e = (case e of
       PExpr1 (PCnst c) \<Rightarrow> PExpr1 (PCnst (- c))
     | _ \<Rightarrow> PExpr1 (PNeg e))"

lemma (in field) npeneg_correct:
  "peval xs (npeneg e) = peval xs (PExpr1 (PNeg e))"
  by (cases e rule: pexpr_cases) (simp_all add: npeneg_def)

lemma option_pair_cases [case_names None Some]:
  assumes
    "x = None \<Longrightarrow> P"
    "\<And>p q. x = Some (p, q) \<Longrightarrow> P"
  shows P
proof (cases x)
  case None
  then show ?thesis by (rule assms)
next
  case (Some r)
  then show ?thesis
    apply (cases r)
    apply simp
    by (rule assms)
qed

fun isin :: "pexpr \<Rightarrow> nat \<Rightarrow> pexpr \<Rightarrow> nat \<Rightarrow> (nat * pexpr) option"
where
  "isin e n (PExpr2 (PMul e1 e2)) m =
     (case isin e n e1 m of
        Some (k, e3) \<Rightarrow>
          if k = 0 then Some (0, npemul e3 (npepow e2 m))
          else (case isin e k e2 m of
              Some (l, e4) \<Rightarrow> Some (l, npemul e3 e4)
            | None \<Rightarrow> Some (k, npemul e3 (npepow e2 m)))
      | None \<Rightarrow> (case isin e n e2 m of
          Some (k, e3) \<Rightarrow> Some (k, npemul (npepow e1 m) e3)
        | None \<Rightarrow> None))"
| "isin e n (PExpr2 (PPow e' k)) m =
     (if k = 0 then None else isin e n e' (k * m))"
| "isin (PExpr1 e) n (PExpr1 e') m =
     (if e = e' then
        if n >= m then Some (n - m, PExpr1 (PCnst 1))
        else Some (0, npepow (PExpr1 e) (m - n))
      else None)"
| "isin (PExpr2 e) n (PExpr1 e') m = None"

lemma (in field) isin_correct:
  assumes "in_carrier xs"
  and "isin e n e' m = Some (p, e'')"
  shows
    "peval xs (PExpr2 (PPow e' m)) =
     peval xs (PExpr2 (PMul (PExpr2 (PPow e (n - p))) e''))"
    "p \<le> n"
  using assms
  by (induct e n e' m arbitrary: p e'' rule: isin.induct)
    (force
       simp add:
         nat_pow_distr nat_pow_pow nat_pow_mult m_ac
         npemul_correct npepow_correct
       split add: option.split_asm prod.split_asm split_if_asm)+

lemma (in field) isin_correct':
  "in_carrier xs \<Longrightarrow> isin e n e' 1 = Some (p, e'') \<Longrightarrow>
   peval xs e' = peval xs e (^) (n - p) \<otimes> peval xs e''"
  "in_carrier xs \<Longrightarrow> isin e n e' 1 = Some (p, e'') \<Longrightarrow> p \<le> n"
  using isin_correct [where m=1]
  by simp_all

fun split_aux :: "pexpr \<Rightarrow> nat \<Rightarrow> pexpr \<Rightarrow> pexpr \<times> pexpr \<times> pexpr"
where
  "split_aux (PExpr2 (PMul e1 e2)) n e =
     (let
        (left1, common1, right1) = split_aux e1 n e;
        (left2, common2, right2) = split_aux e2 n right1
      in (npemul left1 left2, npemul common1 common2, right2))"
| "split_aux (PExpr2 (PPow e' m)) n e =
     (if m = 0 then (PExpr1 (PCnst 1), PExpr1 (PCnst 1), e)
      else split_aux e' (m * n) e)"
| "split_aux (PExpr1 e') n e =
     (case isin (PExpr1 e') n e 1 of
        Some (m, e'') \<Rightarrow>
          (if m = 0 then (PExpr1 (PCnst 1), npepow (PExpr1 e') n, e'')
           else (npepow (PExpr1 e') m, npepow (PExpr1 e') (n - m), e''))
      | None \<Rightarrow> (npepow (PExpr1 e') n, PExpr1 (PCnst 1), e))"

hide_const Left Right

abbreviation Left :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr" where
  "Left e1 e2 \<equiv> fst (split_aux e1 (Suc 0) e2)"

abbreviation Common :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr" where
  "Common e1 e2 \<equiv> fst (snd (split_aux e1 (Suc 0) e2))"

abbreviation Right :: "pexpr \<Rightarrow> pexpr \<Rightarrow> pexpr" where
  "Right e1 e2 \<equiv> snd (snd (split_aux e1 (Suc 0) e2))"

lemma split_aux_induct [case_names 1 2 3]:
  assumes I1: "\<And>e1 e2 n e. P e1 n e \<Longrightarrow> P e2 n (snd (snd (split_aux e1 n e))) \<Longrightarrow>
    P (PExpr2 (PMul e1 e2)) n e"
  and I2: "\<And>e' m n e. (m \<noteq> 0 \<Longrightarrow> P e' (m * n) e) \<Longrightarrow> P (PExpr2 (PPow e' m)) n e"
  and I3: "\<And>e' n e. P (PExpr1 e') n e"
  shows "P x y z"
proof (induct x y z rule: split_aux.induct)
  case 1
  from 1(1) 1(2) [OF refl prod.collapse prod.collapse]
  show ?case by (rule I1)
next
  case 2
  then show ?case by (rule I2)
next
  case 3
  then show ?case by (rule I3)
qed

lemma (in field) split_aux_correct:
  "in_carrier xs \<Longrightarrow>
   peval xs (PExpr2 (PPow e\<^sub>1 n)) =
   peval xs (PExpr2 (PMul (fst (split_aux e\<^sub>1 n e\<^sub>2)) (fst (snd (split_aux e\<^sub>1 n e\<^sub>2)))))"
  "in_carrier xs \<Longrightarrow>
   peval xs e\<^sub>2 =
   peval xs (PExpr2 (PMul (snd (snd (split_aux e\<^sub>1 n e\<^sub>2))) (fst (snd (split_aux e\<^sub>1 n e\<^sub>2)))))"
  by (induct e\<^sub>1 n e\<^sub>2 rule: split_aux_induct)
    (auto simp add: split_beta
       nat_pow_distr nat_pow_pow nat_pow_mult m_ac
       npemul_correct npepow_correct isin_correct'
       split add: option.split)

lemma (in field) split_aux_correct':
  "in_carrier xs \<Longrightarrow>
   peval xs e\<^sub>1 = peval xs (Left e\<^sub>1 e\<^sub>2) \<otimes> peval xs (Common e\<^sub>1 e\<^sub>2)"
  "in_carrier xs \<Longrightarrow>
   peval xs e\<^sub>2 = peval xs (Right e\<^sub>1 e\<^sub>2) \<otimes> peval xs (Common e\<^sub>1 e\<^sub>2)"
  using split_aux_correct [where n=1]
  by simp_all

fun fnorm :: "fexpr \<Rightarrow> pexpr \<times> pexpr \<times> pexpr list"
where
  "fnorm (FCnst c) = (PExpr1 (PCnst c), PExpr1 (PCnst 1), [])"
| "fnorm (FVar n) = (PExpr1 (PVar n), PExpr1 (PCnst 1), [])"
| "fnorm (FAdd e1 e2) =
     (let
        (xn, xd, xc) = fnorm e1;
        (yn, yd, yc) = fnorm e2;
        (left, common, right) = split_aux xd 1 yd
      in
        (npeadd (npemul xn right) (npemul yn left),
         npemul left (npemul right common),
         List.union xc yc))"
| "fnorm (FSub e1 e2) =
     (let
        (xn, xd, xc) = fnorm e1;
        (yn, yd, yc) = fnorm e2;
        (left, common, right) = split_aux xd 1 yd
      in
        (npesub (npemul xn right) (npemul yn left),
         npemul left (npemul right common),
         List.union xc yc))"
| "fnorm (FMul e1 e2) =
     (let
        (xn, xd, xc) = fnorm e1;
        (yn, yd, yc) = fnorm e2;
        (left1, common1, right1) = split_aux xn 1 yd;
        (left2, common2, right2) = split_aux yn 1 xd
      in
        (npemul left1 left2,
         npemul right2 right1,
         List.union xc yc))"
| "fnorm (FNeg e) =
     (let (n, d, c) = fnorm e
      in (npeneg n, d, c))"
| "fnorm (FDiv e1 e2) =
     (let
        (xn, xd, xc) = fnorm e1;
        (yn, yd, yc) = fnorm e2;
        (left1, common1, right1) = split_aux xn 1 yn;
        (left2, common2, right2) = split_aux xd 1 yd
      in
        (npemul left1 right2,
         npemul left2 right1,
         List.insert yn (List.union xc yc)))"
| "fnorm (FPow e m) =
     (let (n, d, c) = fnorm e
      in (npepow n m, npepow d m, c))"

abbreviation Num :: "fexpr \<Rightarrow> pexpr" where
  "Num e \<equiv> fst (fnorm e)"

abbreviation Denom :: "fexpr \<Rightarrow> pexpr" where
  "Denom e \<equiv> fst (snd (fnorm e))"

abbreviation Cond :: "fexpr \<Rightarrow> pexpr list" where
  "Cond e \<equiv> snd (snd (fnorm e))"

primrec (in field) nonzero :: "'a list \<Rightarrow> pexpr list \<Rightarrow> bool"
where
  "nonzero xs [] = True"
| "nonzero xs (p # ps) = (peval xs p \<noteq> \<zero> \<and> nonzero xs ps)"

lemma (in field) nonzero_singleton:
  "nonzero xs [p] = (peval xs p \<noteq> \<zero>)"
  by simp

lemma (in field) nonzero_append:
  "nonzero xs (ps @ qs) = (nonzero xs ps \<and> nonzero xs qs)"
  by (induct ps) simp_all

lemma (in field) nonzero_idempotent:
  "p \<in> set ps \<Longrightarrow> (peval xs p \<noteq> \<zero> \<and> nonzero xs ps) = nonzero xs ps"
  by (induct ps) auto

lemma (in field) nonzero_insert:
  "nonzero xs (List.insert p ps) = (peval xs p \<noteq> \<zero> \<and> nonzero xs ps)"
  by (simp add: List.insert_def nonzero_idempotent)

lemma (in field) nonzero_union:
  "nonzero xs (List.union ps qs) = (nonzero xs ps \<and> nonzero xs qs)"
  by (induct ps rule: rev_induct)
    (auto simp add: List.union_def nonzero_insert nonzero_append)

lemma (in field) fnorm_correct:
  assumes "in_carrier xs"
  and "nonzero xs (Cond e)"
  shows "feval xs e = peval xs (Num e) \<oslash> peval xs (Denom e)"
  and "peval xs (Denom e) \<noteq> \<zero>"
  using assms
proof (induct e)
  case (FCnst c) {
    case 1
    show ?case by simp
  next
    case 2
    show ?case by simp
  }
next
  case (FVar n) {
    case 1
    then show ?case by simp
  next
    case 2
    show ?case by simp
  }
next
  case (FAdd e1 e2)
  note split = split_aux_correct' [where xs=xs and
    e\<^sub>1="Denom e1" and e\<^sub>2="Denom e2"]
  {
    case 1
    let ?left = "peval xs (Left (Denom e1) (Denom e2))"
    let ?common = "peval xs (Common (Denom e1) (Denom e2))"
    let ?right = "peval xs (Right (Denom e1) (Denom e2))"
    from 1 FAdd
    have "feval xs (FAdd e1 e2) =
      (?common \<otimes> (peval xs (Num e1) \<otimes> ?right \<oplus> peval xs (Num e2) \<otimes> ?left)) \<oslash>
      (?common \<otimes> (?left \<otimes> (?right \<otimes> ?common)))"
      by (simp add: split_beta split nonzero_union
        add_frac_eq r_distr m_ac)
    also from 1 FAdd have "\<dots> =
      peval xs (Num (FAdd e1 e2)) \<oslash> peval xs (Denom (FAdd e1 e2))"
      by (simp add: split_beta split nonzero_union npeadd_correct npemul_correct integral_iff)
    finally show ?case .
  next
    case 2
    with FAdd show ?case
      by (simp add: split_beta split nonzero_union npemul_correct integral_iff)
  }
next
  case (FSub e1 e2)
  note split = split_aux_correct' [where xs=xs and
    e\<^sub>1="Denom e1" and e\<^sub>2="Denom e2"]
  {
    case 1
    let ?left = "peval xs (Left (Denom e1) (Denom e2))"
    let ?common = "peval xs (Common (Denom e1) (Denom e2))"
    let ?right = "peval xs (Right (Denom e1) (Denom e2))"
    from 1 FSub
    have "feval xs (FSub e1 e2) =
      (?common \<otimes> (peval xs (Num e1) \<otimes> ?right \<ominus> peval xs (Num e2) \<otimes> ?left)) \<oslash>
      (?common \<otimes> (?left \<otimes> (?right \<otimes> ?common)))"
      by (simp add: split_beta split nonzero_union
        diff_frac_eq r_diff_distr m_ac)
    also from 1 FSub have "\<dots> =
      peval xs (Num (FSub e1 e2)) \<oslash> peval xs (Denom (FSub e1 e2))"
      by (simp add: split_beta split nonzero_union npesub_correct npemul_correct integral_iff)
    finally show ?case .
  next
    case 2
    with FSub show ?case
      by (simp add: split_beta split nonzero_union npemul_correct integral_iff)
  }
next
  case (FMul e1 e2)
  note split =
    split_aux_correct' [where xs=xs and
      e\<^sub>1="Num e1" and e\<^sub>2="Denom e2"]
    split_aux_correct' [where xs=xs and
      e\<^sub>1="Num e2" and e\<^sub>2="Denom e1"]
  {
    case 1
    let ?left\<^sub>1 = "peval xs (Left (Num e1) (Denom e2))"
    let ?common\<^sub>1 = "peval xs (Common (Num e1) (Denom e2))"
    let ?right\<^sub>1 = "peval xs (Right (Num e1) (Denom e2))"
    let ?left\<^sub>2 = "peval xs (Left (Num e2) (Denom e1))"
    let ?common\<^sub>2 = "peval xs (Common (Num e2) (Denom e1))"
    let ?right\<^sub>2 = "peval xs (Right (Num e2) (Denom e1))"
    from 1 FMul
    have "feval xs (FMul e1 e2) =
      ((?common\<^sub>1 \<otimes> ?common\<^sub>2) \<otimes> (?left\<^sub>1 \<otimes> ?left\<^sub>2)) \<oslash>
      ((?common\<^sub>1 \<otimes> ?common\<^sub>2) \<otimes> (?right\<^sub>2 \<otimes> ?right\<^sub>1))"
      by (simp add: split_beta split nonzero_union
        nonzero_divide_divide_eq_left m_ac)
    also from 1 FMul have "\<dots> =
      peval xs (Num (FMul e1 e2)) \<oslash> peval xs (Denom (FMul e1 e2))"
      by (simp add: split_beta split nonzero_union npemul_correct integral_iff)
    finally show ?case .
  next
    case 2
    with FMul show ?case
      by (simp add: split_beta split nonzero_union npemul_correct integral_iff)
  }
next
  case (FNeg e)
  {
    case 1
    with FNeg show ?case
      by (simp add: split_beta npeneg_correct)
  next
    case 2
    with FNeg show ?case
      by (simp add: split_beta)
  }
next
  case (FDiv e1 e2)
  note split =
    split_aux_correct' [where xs=xs and
      e\<^sub>1="Num e1" and e\<^sub>2="Num e2"]
    split_aux_correct' [where xs=xs and
      e\<^sub>1="Denom e1" and e\<^sub>2="Denom e2"]
  {
    case 1
    let ?left\<^sub>1 = "peval xs (Left (Num e1) (Num e2))"
    let ?common\<^sub>1 = "peval xs (Common (Num e1) (Num e2))"
    let ?right\<^sub>1 = "peval xs (Right (Num e1) (Num e2))"
    let ?left\<^sub>2 = "peval xs (Left (Denom e1) (Denom e2))"
    let ?common\<^sub>2 = "peval xs (Common (Denom e1) (Denom e2))"
    let ?right\<^sub>2 = "peval xs (Right (Denom e1) (Denom e2))"
    from 1 FDiv
    have "feval xs (FDiv e1 e2) =
      ((?common\<^sub>1 \<otimes> ?common\<^sub>2) \<otimes> (?left\<^sub>1 \<otimes> ?right\<^sub>2)) \<oslash>
      ((?common\<^sub>1 \<otimes> ?common\<^sub>2) \<otimes> (?left\<^sub>2 \<otimes> ?right\<^sub>1))"
      by (simp add: split_beta split nonzero_union nonzero_insert
        nonzero_divide_divide_eq m_ac)
    also from 1 FDiv have "\<dots> =
      peval xs (Num (FDiv e1 e2)) \<oslash> peval xs (Denom (FDiv e1 e2))"
      by (simp add: split_beta split nonzero_union nonzero_insert npemul_correct integral_iff)
    finally show ?case .
  next
    case 2
    with FDiv show ?case
      by (simp add: split_beta split nonzero_union nonzero_insert npemul_correct integral_iff)
  }
next
  case (FPow e n)
  {
    case 1
    with FPow show ?case
      by (simp add: split_beta nonzero_power_divide npepow_correct)
  next
    case 2
    with FPow show ?case
      by (simp add: split_beta npepow_correct)
  }
qed

lemma (in field) feval_eq0:
  assumes "in_carrier xs"
  and "fnorm e = (n, d, c)"
  and "nonzero xs c"
  and "peval xs n = \<zero>"
  shows "feval xs e = \<zero>"
  using assms fnorm_correct [of xs e]
  by simp

lemma (in field) fexpr_in_carrier:
  assumes "in_carrier xs"
  and "nonzero xs (Cond e)"
  shows "feval xs e \<in> carrier R"
  using assms
proof (induct e)
  case (FDiv e1 e2)
  then have "feval xs e1 \<in> carrier R" "feval xs e2 \<in> carrier R"
    "peval xs (Num e2) \<noteq> \<zero>" "nonzero xs (Cond e2)"
    by (simp_all add: nonzero_union nonzero_insert split add: prod.split_asm)
  from `in_carrier xs` `nonzero xs (Cond e2)`
  have "feval xs e2 = peval xs (Num e2) \<oslash> peval xs (Denom e2)"
    by (rule fnorm_correct)
  moreover from `in_carrier xs` `nonzero xs (Cond e2)`
  have "peval xs (Denom e2) \<noteq> \<zero>" by (rule fnorm_correct)
  ultimately have "feval xs e2 \<noteq> \<zero>" using `peval xs (Num e2) \<noteq> \<zero>` `in_carrier xs`
    by (simp add: divide_eq_0_iff)
  with `feval xs e1 \<in> carrier R` `feval xs e2 \<in> carrier R`
  show ?case by simp
qed (simp_all add: nonzero_union split add: prod.split_asm)

lemma (in field) feval_eq:
  assumes "in_carrier xs"
  and "fnorm (FSub e e') = (n, d, c)"
  and "nonzero xs c"
  shows "(feval xs e = feval xs e') = (peval xs n = \<zero>)"
proof -
  from assms have "nonzero xs (Cond e)" "nonzero xs (Cond e')"
    by (auto simp add: nonzero_union split add: prod.split_asm)
  with assms fnorm_correct [of xs "FSub e e'"]
  have "feval xs e \<ominus> feval xs e' = peval xs n \<oslash> peval xs d"
    "peval xs d \<noteq> \<zero>"
    by simp_all
  show ?thesis
  proof
    assume "feval xs e = feval xs e'"
    with `feval xs e \<ominus> feval xs e' = peval xs n \<oslash> peval xs d`
      `in_carrier xs` `nonzero xs (Cond e')`
    have "peval xs n \<oslash> peval xs d = \<zero>"
      by (simp add: fexpr_in_carrier minus_eq r_neg)
    with `peval xs d \<noteq> \<zero>` `in_carrier xs`
    show "peval xs n = \<zero>"
      by (simp add: divide_eq_0_iff)
  next
    assume "peval xs n = \<zero>"
    with `feval xs e \<ominus> feval xs e' = peval xs n \<oslash> peval xs d` `peval xs d \<noteq> \<zero>`
      `nonzero xs (Cond e)` `nonzero xs (Cond e')` `in_carrier xs`
    show "feval xs e = feval xs e'"
      by (simp add: eq_diff0 fexpr_in_carrier)
  qed
qed

ML {*
signature FIELD_TAC =
sig
  structure Field_Simps:
  sig
    type T
    val get: Context.generic -> T
    val put: T -> Context.generic -> Context.generic
    val map: (T -> T) -> Context.generic -> Context.generic
  end
  val eq_field_simps:
    (term * (thm list * thm list * thm list * thm * thm)) *
    (term * (thm list * thm list * thm list * thm * thm)) -> bool
  val field_tac: bool -> Proof.context -> int -> tactic
end

structure Field_Tac : FIELD_TAC =
struct

open Ring_Tac;

fun field_struct (Const (@{const_name Ring.ring.add}, _) $ R $ _ $ _) = SOME R
  | field_struct (Const (@{const_name Ring.a_minus}, _) $ R $ _ $ _) = SOME R
  | field_struct (Const (@{const_name Group.monoid.mult}, _) $ R $ _ $ _) = SOME R
  | field_struct (Const (@{const_name Ring.a_inv}, _) $ R $ _) = SOME R
  | field_struct (Const (@{const_name Group.pow}, _) $ R $ _ $ _) = SOME R
  | field_struct (Const (@{const_name Algebra_Aux.m_div}, _) $ R $ _ $ _) = SOME R
  | field_struct (Const (@{const_name Ring.ring.zero}, _) $ R) = SOME R
  | field_struct (Const (@{const_name Group.monoid.one}, _) $ R) = SOME R
  | field_struct (Const (@{const_name Algebra_Aux.of_integer}, _) $ R $ _) = SOME R
  | field_struct _ = NONE;

fun reif_fexpr vs (Const (@{const_name Ring.ring.add}, _) $ _ $ a $ b) =
      @{const FAdd} $ reif_fexpr vs a $ reif_fexpr vs b
  | reif_fexpr vs (Const (@{const_name Ring.a_minus}, _) $ _ $ a $ b) =
      @{const FSub} $ reif_fexpr vs a $ reif_fexpr vs b
  | reif_fexpr vs (Const (@{const_name Group.monoid.mult}, _) $ _ $ a $ b) =
      @{const FMul} $ reif_fexpr vs a $ reif_fexpr vs b
  | reif_fexpr vs (Const (@{const_name Ring.a_inv}, _) $ _ $ a) =
      @{const FNeg} $ reif_fexpr vs a
  | reif_fexpr vs (Const (@{const_name Group.pow}, _) $ _ $ a $ n) =
      @{const FPow} $ reif_fexpr vs a $ n
  | reif_fexpr vs (Const (@{const_name Algebra_Aux.m_div}, _) $ _ $ a $ b) =
      @{const FDiv} $ reif_fexpr vs a $ reif_fexpr vs b
  | reif_fexpr vs (Free x) =
      @{const FVar} $ HOLogic.mk_number HOLogic.natT (find_index (equal x) vs)
  | reif_fexpr vs (Const (@{const_name Ring.ring.zero}, _) $ _) =
      @{term "FCnst 0"}
  | reif_fexpr vs (Const (@{const_name Group.monoid.one}, _) $ _) =
      @{term "FCnst 1"}
  | reif_fexpr vs (Const (@{const_name Algebra_Aux.of_integer}, _) $ _ $ n) =
      @{const FCnst} $ n
  | reif_fexpr _ _ = error "reif_fexpr: bad expression";

fun reif_fexpr' vs (Const (@{const_name Groups.plus}, _) $ a $ b) =
      @{const FAdd} $ reif_fexpr' vs a $ reif_fexpr' vs b
  | reif_fexpr' vs (Const (@{const_name Groups.minus}, _) $ a $ b) =
      @{const FSub} $ reif_fexpr' vs a $ reif_fexpr' vs b
  | reif_fexpr' vs (Const (@{const_name Groups.times}, _) $ a $ b) =
      @{const FMul} $ reif_fexpr' vs a $ reif_fexpr' vs b
  | reif_fexpr' vs (Const (@{const_name Groups.uminus}, _) $ a) =
      @{const FNeg} $ reif_fexpr' vs a
  | reif_fexpr' vs (Const (@{const_name Power.power}, _) $ a $ n) =
      @{const FPow} $ reif_fexpr' vs a $ n
  | reif_fexpr' vs (Const (@{const_name divide}, _) $ a $ b) =
      @{const FDiv} $ reif_fexpr' vs a $ reif_fexpr' vs b
  | reif_fexpr' vs (Free x) =
      @{const FVar} $ HOLogic.mk_number HOLogic.natT (find_index (equal x) vs)
  | reif_fexpr' vs (Const (@{const_name zero_class.zero}, _)) =
      @{term "FCnst 0"}
  | reif_fexpr' vs (Const (@{const_name one_class.one}, _)) =
      @{term "FCnst 1"}
  | reif_fexpr' vs (Const (@{const_name numeral}, _) $ b) =
      @{const FCnst} $ (@{const numeral (int)} $ b)
  | reif_fexpr' _ _ = error "reif_fexpr: bad expression";

fun eq_field_simps
  ((t, (ths1, ths2, ths3, th4, th)),
   (t', (ths1', ths2', ths3', th4', th'))) =
    t aconv t' andalso
    eq_list Thm.eq_thm (ths1, ths1') andalso
    eq_list Thm.eq_thm (ths2, ths2') andalso
    eq_list Thm.eq_thm (ths3, ths3') andalso
    Thm.eq_thm (th4, th4') andalso
    Thm.eq_thm (th, th');

structure Field_Simps = Generic_Data
(struct
  type T = (term * (thm list * thm list * thm list * thm * thm)) Net.net
  val empty = Net.empty
  val extend = I
  val merge = Net.merge eq_field_simps
end);

fun get_field_simps ctxt optcT t =
  (case get_matching_rules ctxt (Field_Simps.get (Context.Proof ctxt)) t of
     SOME (ths1, ths2, ths3, th4, th) =>
       let val tr =
         Thm.transfer (Proof_Context.theory_of ctxt) #>
         (case optcT of NONE => I | SOME cT => inst [cT] [] #> norm)
       in (map tr ths1, map tr ths2, map tr ths3, tr th4, tr th) end
   | NONE => error "get_field_simps: lookup failed");

fun nth_el_conv (_, _, _, nth_el_Cons, _) =
  let
    val a = type_of_eqn nth_el_Cons;
    val If_conv_a = If_conv a;

    fun conv ys n = (case strip_app ys of
      (@{const_name Cons}, [x, xs]) =>
        transitive'
          (inst [] [x, xs, n] nth_el_Cons)
          (If_conv_a (args2 nat_eq_conv)
             Thm.reflexive
             (cong2' conv Thm.reflexive (args2 nat_minus_conv))))
  in conv end;

fun feval_conv (rls as
      ([feval_simps_1, feval_simps_2, feval_simps_3,
        feval_simps_4, feval_simps_5, feval_simps_6,
        feval_simps_7, feval_simps_8, feval_simps_9,
        feval_simps_10, feval_simps_11],
       _, _, _, _)) =
  let
    val nth_el_conv' = nth_el_conv rls;

    fun conv xs x = (case strip_app x of
        (@{const_name FCnst}, [c]) => (case strip_app c of
            (@{const_name zero_class.zero}, _) => inst [] [xs] feval_simps_9
          | (@{const_name one_class.one}, _) => inst [] [xs] feval_simps_10
          | (@{const_name numeral}, [n]) => inst [] [xs, n] feval_simps_11
          | _ => inst [] [xs, c] feval_simps_1)
      | (@{const_name FVar}, [n]) =>
          transitive' (inst [] [xs, n] feval_simps_2) (args2 nth_el_conv')
      | (@{const_name FAdd}, [a, b]) =>
          transitive' (inst [] [xs, a, b] feval_simps_3)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name FSub}, [a, b]) =>
          transitive' (inst [] [xs, a, b] feval_simps_4)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name FMul}, [a, b]) =>
          transitive' (inst [] [xs, a, b] feval_simps_5)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name FNeg}, [a]) =>
          transitive' (inst [] [xs, a] feval_simps_6)
            (cong1 (args2 conv))
      | (@{const_name FDiv}, [a, b]) =>
          transitive' (inst [] [xs, a, b] feval_simps_7)
            (cong2 (args2 conv) (args2 conv))
      | (@{const_name FPow}, [a, n]) =>
          transitive' (inst [] [xs, a, n] feval_simps_8)
            (cong2 (args2 conv) Thm.reflexive))
  in conv end;

fun peval_conv (rls as
      (_,
       [peval_simps_1, peval_simps_2, peval_simps_3,
        peval_simps_4, peval_simps_5, peval_simps_6,
        peval_simps_7, peval_simps_8, peval_simps_9,
        peval_simps_10, peval_simps_11],
       _, _, _)) =
  let
    val nth_el_conv' = nth_el_conv rls;

    fun conv xs x = (case strip_app x of
        (@{const_name PExpr1}, [e]) => (case strip_app e of
            (@{const_name PCnst}, [c]) => (case strip_numeral c of
                (@{const_name zero_class.zero}, _) => inst [] [xs] peval_simps_8
              | (@{const_name one_class.one}, _) => inst [] [xs] peval_simps_9
              | (@{const_name numeral}, [n]) => inst [] [xs, n] peval_simps_10
              | (@{const_name uminus}, [n]) => inst [] [xs, n] peval_simps_11
              | _ => inst [] [xs, c] peval_simps_1)
          | (@{const_name PVar}, [n]) =>
              transitive' (inst [] [xs, n] peval_simps_2) (args2 nth_el_conv')
          | (@{const_name PAdd}, [a, b]) =>
              transitive' (inst [] [xs, a, b] peval_simps_3)
                (cong2 (args2 conv) (args2 conv))
          | (@{const_name PSub}, [a, b]) =>
              transitive' (inst [] [xs, a, b] peval_simps_4)
                (cong2 (args2 conv) (args2 conv))
          | (@{const_name PNeg}, [a]) =>
              transitive' (inst [] [xs, a] peval_simps_5)
                (cong1 (args2 conv)))
      | (@{const_name PExpr2}, [e]) => (case strip_app e of
            (@{const_name PMul}, [a, b]) =>
              transitive' (inst [] [xs, a, b] peval_simps_6)
                (cong2 (args2 conv) (args2 conv))
          | (@{const_name PPow}, [a, n]) =>
              transitive' (inst [] [xs, a, n] peval_simps_7)
                (cong2 (args2 conv) Thm.reflexive)))
  in conv end;

fun nonzero_conv (rls as
      (_, _,
       [nonzero_Nil, nonzero_Cons, nonzero_singleton],
       _, _)) =
  let
    val peval_conv' = peval_conv rls;

    fun conv xs qs = (case strip_app qs of
        (@{const_name Nil}, []) => inst [] [xs] nonzero_Nil
      | (@{const_name Cons}, [p, ps]) => (case Thm.term_of ps of
            Const (@{const_name Nil}, _) =>
              transitive' (inst [] [xs, p] nonzero_singleton)
                (cong1 (cong2 (args2 peval_conv') Thm.reflexive))
          | _ => transitive' (inst [] [xs, p, ps] nonzero_Cons)
              (cong2 (cong1 (cong2 (args2 peval_conv') Thm.reflexive)) (args2 conv))))
  in conv end;

fun field_tac in_prem ctxt =
  SUBGOAL (fn (g, i) =>
    let
      val (prems, concl) = Logic.strip_horn g;
      fun find_eq s = (case s of
          (_ $ (Const (@{const_name HOL.eq}, Type (_, [T, _])) $ t $ u)) =>
            (case (field_struct t, field_struct u) of
               (SOME R, _) => SOME ((t, u), R, T, NONE, mk_in_carrier ctxt R [], reif_fexpr)
             | (_, SOME R) => SOME ((t, u), R, T, NONE, mk_in_carrier ctxt R [], reif_fexpr)
             | _ =>
                 if Sign.of_sort (Proof_Context.theory_of ctxt) (T, @{sort field})
                 then SOME ((t, u), mk_ring T, T, SOME T, K @{thm in_carrier_trivial}, reif_fexpr')
                 else NONE)
        | _ => NONE);
      val ((t, u), R, T, optT, mkic, reif) =
        (case get_first find_eq
           (if in_prem then prems else [concl]) of
           SOME q => q
         | NONE => error "cannot determine field");
      val rls as (_, _, _, _, feval_eq) =
        get_field_simps ctxt (Option.map (Thm.ctyp_of ctxt) optT) R;
      val xs = [] |> Term.add_frees t |> Term.add_frees u |> filter (equal T o snd);
      val cxs = Thm.cterm_of ctxt (HOLogic.mk_list T (map Free xs));
      val ce = Thm.cterm_of ctxt (reif xs t);
      val ce' = Thm.cterm_of ctxt (reif xs u);
      val fnorm = Code_Evaluation.dynamic_conv ctxt
        (Thm.apply @{cterm fnorm} (Thm.apply (Thm.apply @{cterm FSub} ce) ce'));
      val (_, [n, dc]) = strip_app (Thm.rhs_of fnorm);
      val (_, [_, c]) = strip_app dc;
      val th =
        Conv.fconv_rule (Conv.concl_conv 1 (Conv.arg_conv
          (binop_conv
             (binop_conv
                (K (feval_conv rls cxs ce)) (K (feval_conv rls cxs ce')))
             (Conv.arg1_conv (K (peval_conv rls cxs n))))))
        ([mkic xs,
          mk_obj_eq fnorm,
          mk_obj_eq (nonzero_conv rls cxs c) RS @{thm iffD2}] MRS
         feval_eq);
      val th' = Drule.rotate_prems 1
        (th RS (if in_prem then @{thm iffD1} else @{thm iffD2}));
    in
      if in_prem then
        dresolve_tac ctxt [th'] 1 THEN defer_tac 1
      else
        resolve_tac ctxt [th'] 1
    end);

end
*}

context field begin

local_setup {*
Local_Theory.declaration {syntax = false, pervasive = false}
  (fn phi => Field_Tac.Field_Simps.map (Ring_Tac.insert_rules Field_Tac.eq_field_simps
    (Morphism.term phi @{term R},
     (Morphism.fact phi @{thms feval.simps [meta] feval_Cnst [meta]},
      Morphism.fact phi @{thms peval.simps [meta] peval_Cnst [meta]},
      Morphism.fact phi @{thms nonzero.simps [meta] nonzero_singleton [meta]},
      singleton (Morphism.fact phi) @{thm nth_el_Cons [meta]},
      singleton (Morphism.fact phi) @{thm feval_eq}))))
*}

end

method_setup field = {*
  Scan.lift (Args.mode "prems") -- Attrib.thms >> (fn (in_prem, thms) => fn ctxt =>
    SIMPLE_METHOD' (Field_Tac.field_tac in_prem ctxt THEN' Ring_Tac.ring_tac in_prem thms ctxt))
*} "reduce equations over fields to equations over rings"

end
