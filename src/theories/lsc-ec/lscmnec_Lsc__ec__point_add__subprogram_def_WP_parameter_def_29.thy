theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_29
imports
  "../Elliptic_Spec"
  "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_29.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  def A \<equiv> "num_of_big_int (word32_to_int \<circ> elts a) a_first ?L"
  def X\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x1) x1_first ?L"
  def Y\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y1) y1_first ?L"
  def Z\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z1) z1_first ?L"
  def X\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x2) x2_first ?L"
  def Y\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y2) y2_first ?L"
  def Z\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z2) z2_first ?L"
  def X\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> x3) x3_first ?L"
  def Y\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> y3) y3_first ?L"
  def Z\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> z3) z3_first ?L"
  def AA \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mod_add__a) 0 ?L"
  def SA \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mod_sub__a) 0 ?L"
  def SA\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mod_sub__a1) 0 ?L"
  def SIA \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mod_sub_inplace__a) 0 ?L"
  def SIA\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mod_sub_inplace__a1) 0 ?L"
  def MA \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a) 0 ?L"
  def MA\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a1) 0 ?L"
  def MA\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a2) 0 ?L"
  def MA\<^sub>3 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a3) 0 ?L"
  def MA\<^sub>4 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a4) 0 ?L"
  def MA\<^sub>5 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a5) 0 ?L"
  def MA\<^sub>6 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a6) 0 ?L"
  def MA\<^sub>7 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a7) 0 ?L"
  def MA\<^sub>8 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a8) 0 ?L"
  def MA\<^sub>9 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a9) 0 ?L"
  def MA\<^sub>1\<^sub>0 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a10) 0 ?L"
  def MA\<^sub>1\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a11) 0 ?L"
  def MA\<^sub>1\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> lsc__bignum__mont_mult__a12) 0 ?L"
  def INV \<equiv> "minv M (int_of_math_int (base ())) ^ nat ?L"

  note defs [symmetric] =
    M_def A_def X\<^sub>1_def Y\<^sub>1_def Z\<^sub>1_def X\<^sub>2_def Y\<^sub>2_def Z\<^sub>2_def X\<^sub>3_def Y\<^sub>3_def Z\<^sub>3_def
    AA_def
    SA_def SA\<^sub>1_def
    SIA_def SIA\<^sub>1_def
    MA_def MA\<^sub>1_def MA\<^sub>2_def MA\<^sub>3_def MA\<^sub>4_def MA\<^sub>5_def MA\<^sub>6_def MA\<^sub>7_def MA\<^sub>9_def MA\<^sub>1\<^sub>0_def MA\<^sub>1\<^sub>1_def MA\<^sub>1\<^sub>2_def
    INV_def

  note defs' [my_simplified defs mk_bounds_eqs integer_in_range_def slide_eq] =
    `(num_of_big_int' (Array x3 _) _ _ = _) = _`
    `(num_of_big_int' (Array y3 _) _ _ = _) = _`
    `(num_of_big_int' (Array z3 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_add__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_sub__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_sub__a1 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_sub_inplace__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_sub_inplace__a1 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a1 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a2 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a3 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a4 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a5 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a6 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a7 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a8 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a9 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a10 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a11 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a12 _) _ _ = _) = _`

  note m_inv = `_ + m_inv * elts m m_first = _`
    [simplified word_uint_eq_iff uint_word_ariths, simplified,
     folded word32_to_int_def]

  from `x1_first < x1_last` `(math_int_from_word _ < num_of_big_int' m _ _) = _`
  have Base_inv: "Base * minv M Base mod M = 1"
    by (simp add: lint_inv_mod [of "\<lfloor>m_inv\<rfloor>\<^sub>s" "word32_to_int o elts m" _ 32, simplified, OF m_inv]
      M_def del: num_of_lint_sum)

  from `(math_int_from_word (ring_1_class.of_int 1) < num_of_big_int' m _ _) = _`
  interpret residues M "residue_ring M"
    by (simp_all add: residues_def M_def)

  from
    `is_zero z1 _ _ \<noteq> _`
    `(is_zero z1 _ _ = _) = _`
  have "Z\<^sub>1 \<noteq> 0" by (simp add: Z\<^sub>1_def)
  moreover from
    `is_zero z2 _ _ \<noteq> _`
    `(is_zero z2 _ _ = _) = _`
  have "Z\<^sub>2 \<noteq> 0" by (simp add: Z\<^sub>2_def)
  moreover from
    `(math_int_from_word _ < num_of_big_int' m m_first (x1_last - x1_first + 1)) = _`
    `is_zero (Array (slide lsc__bignum__mod_sub__a _ _) _) _ _ \<noteq> _`
    `(is_zero (Array (slide lsc__bignum__mod_sub__a _ _) _) _ _ = _) = _`
  have "(X\<^sub>2 * Z\<^sub>1 - X\<^sub>1 * Z\<^sub>2) * INV mod M \<noteq> 0"
    by (simp add: mk_bounds_eqs integer_in_range_def slide_eq defs defs' mod_sub_eq ring_distribs)
  then have "(X\<^sub>2 * Z\<^sub>1 - X\<^sub>1 * Z\<^sub>2) mod M \<noteq> 0"
    by (simp add: INV_def base_eq eq0_inv_iff' [OF Base_inv])   
  ultimately show ?thesis
  proof (simp add: point_add_spec_def Let_def proj_eq_def padd_def
    zero_cong res_mult_eq res_add_eq res_diff_cong
    res_of_int_eq res_pow_eq defs defs',
    intro impI conjI, goal_cases)
    case 1
    let "?l = ?r" = ?case
    have "?l = ((X\<^sub>2 * Z\<^sub>1 - X\<^sub>1 * Z\<^sub>2) ^ 3 * Z\<^sub>1 * Z\<^sub>2 * INV ^ 7 mod M = 0)"
      by (simp add: INV_def base_eq eq0_inv_iff' [OF Base_inv] power_mult [symmetric])
    also have "\<dots> = ?r"
      by (simp add: eval_nat_numeral mult_ac ring_distribs)
    finally show ?case .
  next
    case 2
    show ?case
      apply (rule arg_cong [where f="\<lambda>x. x mod M"])
      apply (rule eq_iff_diff_eq_0 [THEN iffD2])
      apply ring
      done
  next
    case 3
    show ?case
      apply (rule arg_cong [where f="\<lambda>x. x mod M"])
      apply (rule eq_iff_diff_eq_0 [THEN iffD2])
      apply ring
      done
  qed
qed

why3_end

end
