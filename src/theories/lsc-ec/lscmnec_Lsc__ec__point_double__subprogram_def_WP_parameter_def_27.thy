theory lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_27
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_double__subprogram_def_WP_parameter_def_27.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"
  def A \<equiv> "num_of_big_int (word32_to_int \<circ> elts a) a_first ?L"
  def X\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts x1) x1_first ?L"
  def Y\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts y1) y1_first ?L"
  def Z\<^sub>1 \<equiv> "num_of_big_int (word32_to_int \<circ> elts z1) z1_first ?L"
  def X\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> x2) x2_first ?L"
  def Y\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> y2) y2_first ?L"
  def Z\<^sub>2 \<equiv> "num_of_big_int (word32_to_int \<circ> z2) z2_first ?L"

  note defs [symmetric] =
    M_def A_def X\<^sub>1_def Y\<^sub>1_def Z\<^sub>1_def X\<^sub>2_def Y\<^sub>2_def Z\<^sub>2_def

  from `(math_int_from_word (ring_1_class.of_int 1) < num_of_big_int' m _ _) = _`
  interpret residues M "residue_ring M"
    by (simp_all add: residues_def M_def)

  from `\<forall>k. _ \<longrightarrow> z2 k = _`
  have "Z\<^sub>2 = 0"
    by (simp add: Z\<^sub>2_def num_of_lint_all0 word32_to_int_def)
  with `_ = ((num_of_big_int' z1 _ _ = _) = _)` [my_simplified defs]
    `is_zero z1 z1_first (z1_first + (x1_last - x1_first)) = _`
  show ?thesis
    by (simp add: point_double_spec_def Let_def proj_eq_def pdouble_def
      zero_cong res_mult_eq res_add_eq res_diff_cong
      res_of_int_eq res_pow_eq defs)
qed

why3_end

end
