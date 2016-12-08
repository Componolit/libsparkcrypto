theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_11
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_11.xml"

why3_vc WP_parameter_def
proof (simp add: two_point_mult_spec_def Let_def, (rule allI impI)+, goal_cases)
  case (1 b)
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  def A \<equiv> "num_of_big_int (word32_to_int \<circ> elts a) a_first ?L"
  def X\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x1) x1_first ?L"
  def Y\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y1) y1_first ?L"
  def Z\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z1) z1_first ?L"
  def X\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x2) x2_first ?L"
  def Y\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y2) y2_first ?L"
  def Z\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z2) z2_first ?L"
  def X\<^sub>3\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> x32) x3_first ?L"
  def Y\<^sub>3\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> y32) y3_first ?L"
  def Z\<^sub>3\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> z32) z3_first ?L"
  def X\<^sub>3\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> x33) x3_first ?L"
  def Y\<^sub>3\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> y33) y3_first ?L"
  def Z\<^sub>3\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> z33) z3_first ?L"
  def DX\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__x2) 0 ?L"
  def DY\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__y2) 0 ?L"
  def DZ\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__z2) 0 ?L"
  def INV \<equiv> "minv M (int_of_math_int (base ())) ^ nat ?L"
  let ?e1 = "num_of_big_int (word32_to_int \<circ> elts e1) (o1 + 1) (e1_last - o1)"
  let ?e2 = "num_of_big_int (word32_to_int \<circ> elts e2) (e2_first + (o1 - e1_first) + 1) (e1_last - o1)"
  let ?a = "A * INV mod M"

  note defs [symmetric] =
    M_def A_def X\<^sub>1_def Y\<^sub>1_def Z\<^sub>1_def X\<^sub>2_def Y\<^sub>2_def Z\<^sub>2_def
    X\<^sub>3\<^sub>2_def Y\<^sub>3\<^sub>2_def Z\<^sub>3\<^sub>2_def X\<^sub>3\<^sub>3_def Y\<^sub>3\<^sub>3_def Z\<^sub>3\<^sub>3_def
    DX\<^sub>2_def DY\<^sub>2_def DZ\<^sub>2_def
    INV_def

  note bit1 = `(if (if elts e1 o1 AND of_int 2 ^ nat j =
    of_int 0 then _ else _) \<noteq> _ then _ else _) = _`

  note nonsingular = `ell_field.nonsingular _ _ b` [simplified defs]
  note on_curvep1 = `cring.on_curvep _ _ b (num_of_big_int (word32_to_int \<circ> elts x1) _ _, _, _)` [simplified defs]
  note on_curvep2 = `cring.on_curvep _ _ b (num_of_big_int (word32_to_int \<circ> elts x2) _ _, _, _)` [simplified defs]
  note prime = `prime (nat _)` [simplified defs]

  then interpret residues_prime_ell "nat M" "residue_ring M"
    rewrites "int (nat M) = M"
    by unfold_locales (insert `2 < _`, simp_all add: defs)

  let ?x1 = "make_affine (X\<^sub>1, Y\<^sub>1, Z\<^sub>1)"
  let ?x2 = "make_affine (X\<^sub>2, Y\<^sub>2, Z\<^sub>2)"

  from gt2
  have ge0: "0 \<le> A" "0 \<le> INV" "0 \<le> X\<^sub>3\<^sub>2" "0 \<le> Y\<^sub>3\<^sub>2" "0 \<le> Z\<^sub>3\<^sub>2" "0 \<le> X\<^sub>3\<^sub>3" "0 \<le> Y\<^sub>3\<^sub>3" "0 \<le> Z\<^sub>3\<^sub>3"
    "0 \<le> DX\<^sub>2" "0 \<le> DY\<^sub>2" "0 \<le> DZ\<^sub>2"
    by (simp_all add: A_def INV_def X\<^sub>3\<^sub>2_def Y\<^sub>3\<^sub>2_def Z\<^sub>3\<^sub>2_def X\<^sub>3\<^sub>3_def Y\<^sub>3\<^sub>3_def Z\<^sub>3\<^sub>3_def
      DX\<^sub>2_def DY\<^sub>2_def DZ\<^sub>2_def
      num_of_lint_lower word32_to_int_lower
      base_eq minv_def)

  from gt2 have "2 < M" by simp

  with gt2 have a: "?a \<in> carrier (residue_ring M)"
    by (simp add: res_carrier_eq defs)

  note bM = `b < _` [simplified defs]
  with `0 \<le> b`
  have b: "b \<in> carrier (residue_ring M)"
    by (simp add: res_carrier_eq)

  from ge0
    `(num_of_big_int' (Array x32 _) _ _ < _) = _`
    `(num_of_big_int' (Array y32 _) _ _ < _) = _`
    `(num_of_big_int' (Array z32 _) _ _ < _) = _`
  have p\<^sub>3\<^sub>2: "in_carrierp (X\<^sub>3\<^sub>2, Y\<^sub>3\<^sub>2, Z\<^sub>3\<^sub>2)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  from ge0
    `(num_of_big_int' (Array x33 _) _ _ < _) = _`
    `(num_of_big_int' (Array y33 _) _ _ < _) = _`
    `(num_of_big_int' (Array z33 _) _ _ < _) = _`
  have p\<^sub>3\<^sub>3: "in_carrierp (X\<^sub>3\<^sub>3, Y\<^sub>3\<^sub>3, Z\<^sub>3\<^sub>3)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  from ge0
    `(num_of_big_int' (Array lsc__ec__point_double__x2 _) _ _ < _) = _`
    `(num_of_big_int' (Array lsc__ec__point_double__y2 _) _ _ < _) = _`
    `(num_of_big_int' (Array lsc__ec__point_double__z2 _) _ _ < _) = _`
  have d\<^sub>2: "in_carrierp (DX\<^sub>2, DY\<^sub>2, DZ\<^sub>2)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  note eq1 =
    `two_point_mult_spec _ _ _ _ _ _ _ _ _ _ (num_of_big_int' (Array x32 _) _ _) _ _ = _`
      [my_simplified two_point_mult_spec_def Let_def prime defs,
       rule_format, OF `2 < M` `0 \<le> b` bM nonsingular on_curvep1 on_curvep2,
       my_simplified a b p\<^sub>3\<^sub>2 on_curvep1 on_curvep2
       on_curvep_imp_in_carrierp [of ?a b] ppoint_mult_correct [of _ b]
       padd_correct [of _ b] padd_closed
       make_affine_proj_eq_iff, symmetric]

  with a b on_curvep1 on_curvep2
  have p\<^sub>3\<^sub>2': "on_curvep ?a b (X\<^sub>3\<^sub>2, Y\<^sub>3\<^sub>2, Z\<^sub>3\<^sub>2)"
    by (simp add: on_curvep_iff_on_curve [OF a b p\<^sub>3\<^sub>2] point_mult_closed add_closed
      on_curvep_iff_on_curve [symmetric])

  note eq2 =
    `point_double_spec _ _ (num_of_big_int' (Array x32 _) _ _) _ _ _ _ _ = _`
      [my_simplified point_double_spec_def Let_def defs
       make_affine_proj_eq_iff a p\<^sub>3\<^sub>2 d\<^sub>2 pdouble_in_carrierp pdouble_correct,
       symmetric]

  with a b p\<^sub>3\<^sub>2'
  have d\<^sub>2': "on_curvep ?a b (DX\<^sub>2, DY\<^sub>2, DZ\<^sub>2)"
    by (simp add: on_curvep_iff_on_curve [OF a b d\<^sub>2] add_closed
      on_curvep_iff_on_curve [symmetric])

  note eq3 =
    `point_add_spec _ _ _ _ _ _ _ _ (num_of_big_int' (Array x33 _) _ _) _ _ = _`
      [my_simplified point_add_spec_def Let_def slide_eq mk_bounds_eqs integer_in_range_def defs
       make_affine_proj_eq_iff a b p\<^sub>3\<^sub>3 d\<^sub>2' padd_in_carrierp padd_correct [of _ b]
       on_curvep1 on_curvep_imp_in_carrierp [of ?a b], symmetric]

  with a b d\<^sub>2' on_curvep1
  have p\<^sub>3\<^sub>3': "on_curvep ?a b (X\<^sub>3\<^sub>3, Y\<^sub>3\<^sub>3, Z\<^sub>3\<^sub>3)"
    by (simp add: on_curvep_iff_on_curve [OF a b p\<^sub>3\<^sub>3] add_closed
      on_curvep_iff_on_curve [symmetric])

  from eq1 eq2 eq3 a b nonsingular on_curvep1 on_curvep2
  have "make_affine (X\<^sub>3\<^sub>3, Y\<^sub>3\<^sub>3, Z\<^sub>3\<^sub>3) =
    add ?a
      (add ?a
         (point_mult ?a
            (nat ((?e1 * 2 ^ nat (31 - j) +
               \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2))
            ?x1)
         (point_mult ?a
            (nat ((?e2 * 2 ^ nat (31 - j) +
               \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2))
            ?x2))
      ?x1"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult.commute])
      (simp add: point_mult_mult point_mult2_eq_double word32_to_int_def
        on_curvep_iff_on_curve [symmetric] add_assoc [symmetric] add_comm add_comm'
        add_closed point_mult_closed)
  also from a b nonsingular on_curvep1 on_curvep2 have "\<dots> =
    add ?a
      (point_mult ?a
         (nat ((?e1 * 2 ^ nat (31 - j) +
            \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1))
         ?x1)
      (point_mult ?a
         (nat ((?e2 * 2 ^ nat (31 - j) +
            \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2))
         ?x2)"
    by (simp add: nat_add_distrib num_of_lint_lower word32_to_int_lower
      pos_imp_zdiv_nonneg_iff on_curvep_iff_on_curve [symmetric]
      add_comm add_comm' add_closed point_mult_closed)
  also from `0 \<le> j` `j \<le> 31`
  have "(?e1 * 2 ^ nat (31 - j) +
      \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1 =
    ?e1 * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 + 1"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult.commute [of _ 2]])
  also from bit1
    power_increasing [OF nat_mono [OF `j \<le> 31`], of "2::int"]
  have "\<dots> = ?e1 * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 +
    \<lfloor>elts e1 o1\<rfloor>\<^sub>s div 2 ^ nat j mod 2"
    by (simp add: AND_div_mod word_uint_eq_iff uint_pow uint_and
      word32_to_int_def)
  also from `0 \<le> j` `j \<le> 31`
  have "(?e2 * 2 ^ nat (31 - j) +
      \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 =
    ?e2 * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult.commute [of _ 2]])
  also from `(if (if elts e2 (e2_first + (o1 - e1_first)) AND of_int 2 ^ nat j = of_int 0
    then _ else _) \<noteq> _ then _ else _) \<noteq> _`
    power_increasing [OF nat_mono [OF `j \<le> 31`], of "2::int"]
  have "\<dots> = ?e2 * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 +
    \<lfloor>elts e2 (e2_first + (o1 - e1_first))\<rfloor>\<^sub>s div 2 ^ nat j mod 2"
    by (simp add: AND_div_mod word_uint_eq_iff uint_and uint_pow
      word32_to_int_def)
  finally show ?case
    by (simp add: defs make_affine_proj_eq_iff on_curvep1 on_curvep2 p\<^sub>3\<^sub>3' a b
      ppoint_mult_correct [of _ b] on_curvep_imp_in_carrierp [of ?a b]
      padd_correct [of _ b] padd_closed)
      (simp add: add.commute word32_to_int_def o_def)
qed

why3_end

end
