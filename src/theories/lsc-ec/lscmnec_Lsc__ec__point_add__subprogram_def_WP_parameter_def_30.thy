theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_30
imports "../Elliptic_Spec" "../Point_Add"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_30.xml"

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
  def INV \<equiv> "minv M (int_of_math_int (base ())) ^ nat ?L"

  note defs [symmetric] =
    M_def A_def X\<^sub>1_def Y\<^sub>1_def Z\<^sub>1_def X\<^sub>2_def Y\<^sub>2_def Z\<^sub>2_def X\<^sub>3_def Y\<^sub>3_def Z\<^sub>3_def
    INV_def

  note defs' [my_simplified defs mk_bounds_eqs integer_in_range_def slide_eq] =
    `(num_of_big_int' (Array lsc__bignum__mod_sub__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mod_sub__a1 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a1 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a2 _) _ _ = _) = _`
    `(num_of_big_int' (Array lsc__bignum__mont_mult__a3 _) _ _ = _) = _`

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
    `_ = ((num_of_big_int' (Array (slide lsc__bignum__mod_sub__a _ _) _) _ _ = _) = _)`
    `is_zero (Array (slide lsc__bignum__mod_sub__a _ _) _) _ _ = _`
  have "(X\<^sub>2 * Z\<^sub>1 - X\<^sub>1 * Z\<^sub>2) * INV mod M = 0"
    by (simp add: mk_bounds_eqs integer_in_range_def slide_eq defs defs' mod_sub_eq ring_distribs)
  then have "(X\<^sub>2 * Z\<^sub>1 - X\<^sub>1 * Z\<^sub>2) mod M = 0"
    by (simp add: INV_def base_eq eq0_inv_iff' [OF Base_inv])   
  moreover from
    `(math_int_from_word _ < num_of_big_int' m m_first (x1_last - x1_first + 1)) = _`
    `is_zero (Array (slide lsc__bignum__mod_sub__a1 _ _) _) _ _ \<noteq> _`
    `(is_zero (Array (slide lsc__bignum__mod_sub__a1 _ _) _) _ _ = _) = _`
  have "(Y\<^sub>2 * Z\<^sub>1 - Y\<^sub>1 * Z\<^sub>2) * INV mod M \<noteq> 0"
    by (simp add: mk_bounds_eqs integer_in_range_def slide_eq defs defs' mod_sub_eq ring_distribs)
  then have "(Y\<^sub>2 * Z\<^sub>1 - Y\<^sub>1 * Z\<^sub>2) mod M \<noteq> 0"
    by (simp add: INV_def base_eq eq0_inv_iff' [OF Base_inv])
  moreover from `\<forall>k. _ \<longrightarrow> z3 k = _`
  have "Z\<^sub>3 = 0" by (simp add: Z\<^sub>3_def num_of_lint_all0 word32_to_int_def)
  ultimately show ?thesis
    by (simp add: point_add_spec_def Let_def proj_eq_def padd_def
      zero_cong res_mult_eq res_add_eq res_diff_cong
      res_of_int_eq res_pow_eq defs defs' map__content_def)
qed

why3_end

end
