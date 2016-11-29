theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_9
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_9.xml"

why3_vc WP_parameter_def
proof (simp add: point_mult_spec_def Let_def, (rule allI impI)+, goal_cases)
  case (1 b)
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  def A \<equiv> "num_of_big_int (word32_to_int \<circ> elts a) a_first ?L"
  def X\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x1) x1_first ?L"
  def Y\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y1) y1_first ?L"
  def Z\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z1) z1_first ?L"
  def X\<^sub>2\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> x22) x2_first ?L"
  def Y\<^sub>2\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> y22) y2_first ?L"
  def Z\<^sub>2\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> z22) z2_first ?L"
  def X\<^sub>2\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> x23) x2_first ?L"
  def Y\<^sub>2\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> y23) y2_first ?L"
  def Z\<^sub>2\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> z23) z2_first ?L"
  def DX\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__x2) 0 ?L"
  def DY\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__y2) 0 ?L"
  def DZ\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__ec__point_double__z2) 0 ?L"
  def INV \<equiv> "minv M (int_of_math_int (base ())) ^ nat ?L"
  let ?e = "num_of_big_int (word32_to_int \<circ> elts e) (o1 + 1) (e_last - o1)"
  let ?a = "A * INV mod M"

  note defs [symmetric] =
    M_def A_def X\<^sub>1_def Y\<^sub>1_def Z\<^sub>1_def X\<^sub>2\<^sub>2_def Y\<^sub>2\<^sub>2_def Z\<^sub>2\<^sub>2_def X\<^sub>2\<^sub>3_def Y\<^sub>2\<^sub>3_def Z\<^sub>2\<^sub>3_def
    DX\<^sub>2_def DY\<^sub>2_def DZ\<^sub>2_def
    INV_def

  note bit = `_ = (if (if elts e o1 AND _ ^ nat j = _ then _ else _) \<noteq> _ then _ else _)`

  note nonsingular = `ell_field.nonsingular _ _ b` [simplified defs]
  note on_curvep = `cring.on_curvep _ _ b _` [simplified defs]
  note prime = `prime (nat _)` [simplified defs]

  then interpret residues_prime_ell "nat M" "residue_ring M"
    rewrites "int (nat M) = M"
    by unfold_locales (insert `2 < _`, simp_all add: defs)

  let ?x = "make_affine (X\<^sub>1, Y\<^sub>1, Z\<^sub>1)"

  from gt2
  have ge0: "0 \<le> A" "0 \<le> INV" "0 \<le> X\<^sub>2\<^sub>2" "0 \<le> Y\<^sub>2\<^sub>2" "0 \<le> Z\<^sub>2\<^sub>2" "0 \<le> DX\<^sub>2" "0 \<le> DY\<^sub>2" "0 \<le> DZ\<^sub>2"
    "0 \<le> X\<^sub>2\<^sub>3" "0 \<le> Y\<^sub>2\<^sub>3" "0 \<le> Z\<^sub>2\<^sub>3"
    by (simp_all add: A_def INV_def X\<^sub>2\<^sub>2_def Y\<^sub>2\<^sub>2_def Z\<^sub>2\<^sub>2_def DX\<^sub>2_def DY\<^sub>2_def DZ\<^sub>2_def
      X\<^sub>2\<^sub>3_def Y\<^sub>2\<^sub>3_def Z\<^sub>2\<^sub>3_def num_of_lint_lower word32_to_int_lower
      base_eq minv_def)

  from gt2 have "2 < M" by simp

  with gt2 have a: "?a \<in> carrier (residue_ring M)"
    by (simp add: res_carrier_eq defs)

  note bM = `b < _` [simplified defs]
  with `0 \<le> b`
  have b: "b \<in> carrier (residue_ring M)"
    by (simp add: res_carrier_eq)

  from ge0
    `(num_of_big_int' (Array x22 _) _ _ < _) = _`
    `(num_of_big_int' (Array y22 _) _ _ < _) = _`
    `(num_of_big_int' (Array z22 _) _ _ < _) = _`
  have p\<^sub>2\<^sub>2: "in_carrierp (X\<^sub>2\<^sub>2, Y\<^sub>2\<^sub>2, Z\<^sub>2\<^sub>2)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  from ge0
    `(num_of_big_int' (Array x23 _) _ _ < _) = _`
    `(num_of_big_int' (Array y23 _) _ _ < _) = _`
    `(num_of_big_int' (Array z23 _) _ _ < _) = _`
  have p\<^sub>2\<^sub>3: "in_carrierp (X\<^sub>2\<^sub>3, Y\<^sub>2\<^sub>3, Z\<^sub>2\<^sub>3)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  from ge0
    `(num_of_big_int' (Array lsc__ec__point_double__x2 _) _ _ < _) = _`
    `(num_of_big_int' (Array lsc__ec__point_double__y2 _) _ _ < _) = _`
    `(num_of_big_int' (Array lsc__ec__point_double__z2 _) _ _ < _) = _`
  have d\<^sub>2: "in_carrierp (DX\<^sub>2, DY\<^sub>2, DZ\<^sub>2)"
    by (simp add: in_carrierp_def res_carrier_eq defs)

  note eq1 =
    `point_mult_spec _ _ _ _ _ _ (num_of_big_int' (Array x22 _) _ _) _ _ = _`
      [my_simplified point_mult_spec_def Let_def on_curvep prime defs,
       rule_format, OF `2 < M` `0 \<le> b` bM nonsingular on_curvep,
       my_simplified a b p\<^sub>2\<^sub>2 on_curvep
       on_curvep_imp_in_carrierp [of ?a b] ppoint_mult_correct [of _ b]
       make_affine_proj_eq_iff, symmetric]

  with a b on_curvep
  have p\<^sub>2\<^sub>2': "on_curvep ?a b (X\<^sub>2\<^sub>2, Y\<^sub>2\<^sub>2, Z\<^sub>2\<^sub>2)"
    by (simp add: on_curvep_iff_on_curve [OF a b p\<^sub>2\<^sub>2] point_mult_closed
      on_curvep_iff_on_curve [symmetric])

  note eq2 =
    `point_double_spec _ _ (num_of_big_int' (Array x22 _) _ _) _ _ _ _ _ = _`
      [my_simplified point_double_spec_def Let_def defs
       make_affine_proj_eq_iff a p\<^sub>2\<^sub>2 d\<^sub>2 pdouble_in_carrierp pdouble_correct,
       symmetric]

  with a b p\<^sub>2\<^sub>2'
  have d\<^sub>2': "on_curvep ?a b (DX\<^sub>2, DY\<^sub>2, DZ\<^sub>2)"
    by (simp add: on_curvep_iff_on_curve [OF a b d\<^sub>2] add_closed
      on_curvep_iff_on_curve [symmetric])

  note eq3 =
    `point_add_spec _ _ _ _ _ _ _ _ (num_of_big_int' (Array x23 _) _ _) _ _ = _`
      [my_simplified point_add_spec_def Let_def slide_eq mk_bounds_eqs integer_in_range_def defs
       make_affine_proj_eq_iff a b p\<^sub>2\<^sub>3 d\<^sub>2' padd_in_carrierp padd_correct [of _ b]
       on_curvep on_curvep_imp_in_carrierp [of ?a b], symmetric]

  with a b d\<^sub>2' on_curvep
  have p\<^sub>2\<^sub>3': "on_curvep ?a b (X\<^sub>2\<^sub>3, Y\<^sub>2\<^sub>3, Z\<^sub>2\<^sub>3)"
    by (simp add: on_curvep_iff_on_curve [OF a b p\<^sub>2\<^sub>3] add_closed
      on_curvep_iff_on_curve [symmetric])

  from eq1 eq2 eq3 a b nonsingular on_curvep
  have "make_affine (X\<^sub>2\<^sub>3, Y\<^sub>2\<^sub>3, Z\<^sub>2\<^sub>3) =
    add ?a
      (point_mult ?a
         (nat ((?e * 2 ^ nat (31 - j) +
            \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2))
         ?x)
      ?x"
    by (simp only: nat_mult_distrib [of 2, simplified, simplified mult.commute])
      (simp add: point_mult_mult point_mult2_eq_double word32_to_int_def
        on_curvep_iff_on_curve [symmetric])
  also from a b on_curvep have "\<dots> =
    point_mult ?a (nat ((?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1)) ?x"
    by (simp add: nat_add_distrib num_of_lint_lower word32_to_int_lower
      pos_imp_zdiv_nonneg_iff
      on_curvep_iff_on_curve [symmetric] add_comm point_mult_closed)
  also from `0 \<le> j` `j \<le> 31`
  have "(?e * 2 ^ nat (31 - j) +
      \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat (j + 1)) * 2 + 1 =
    ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 + 1"
    by (simp only: nat_add_distrib)
      (simp add: zdiv_zmult2_eq [of 2, simplified mult.commute [of _ 2]])
  also from bit
    power_increasing [OF nat_mono [OF `j \<le> 31`], of "2::int"]
  have "\<dots> = ?e * 2 ^ nat (31 - j + 1) +
    \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat j div 2 * 2 +
    \<lfloor>elts e o1\<rfloor>\<^sub>s div 2 ^ nat j mod 2"
    by (simp add: AND_div_mod word_uint_eq_iff uint_and uint_pow
      word32_to_int_def)
  finally show ?case
    by (simp add: defs make_affine_proj_eq_iff on_curvep p\<^sub>2\<^sub>3' a b
      ppoint_mult_correct [of _ b] on_curvep_imp_in_carrierp [of ?a b])
      (simp add: add.commute word32_to_int_def)
qed

why3_end

end
