theory lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_33
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_add__subprogram_def_WP_parameter_def_33.xml"

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

  from `(math_int_from_word (ring_1_class.of_int 1) < num_of_big_int' m _ _) = _`
  interpret residues M "residue_ring M"
    by (simp_all add: residues_def M_def)

  from
    `_ = ((num_of_big_int' z1 _ _ = _) = _)`
  have "Z\<^sub>1 = 0" by (simp add: Z\<^sub>1_def)
  moreover from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> x3 k = _) \<and> _`
    `\<lfloor>x3__first\<rfloor>\<^sub>\<int> \<le> x3_first`
    `x3_first + (x1_last - x1_first) \<le> \<lfloor>x3__last\<rfloor>\<^sub>\<int>`
  have "X\<^sub>3 = X\<^sub>2"
    by (simp add: X\<^sub>2_def X\<^sub>3_def add_diff_eq num_of_lint_ext)
  moreover from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> y3 k = _) \<and> _`
    `\<lfloor>y3__first\<rfloor>\<^sub>\<int> \<le> y3_first`
    `y3_first + (x1_last - x1_first) \<le> \<lfloor>y3__last\<rfloor>\<^sub>\<int>`
  have "Y\<^sub>3 = Y\<^sub>2"
    by (simp add: Y\<^sub>2_def Y\<^sub>3_def add_diff_eq num_of_lint_ext)
  moreover from
    `\<forall>k. _ \<longrightarrow> (_ \<longrightarrow> z3 k = _) \<and> _`
    `\<lfloor>z3__first\<rfloor>\<^sub>\<int> \<le> z3_first`
    `z3_first + (x1_last - x1_first) \<le> \<lfloor>z3__last\<rfloor>\<^sub>\<int>`
  have "Z\<^sub>3 = Z\<^sub>2"
    by (simp add: Z\<^sub>2_def Z\<^sub>3_def add_diff_eq num_of_lint_ext)
  ultimately show ?thesis
    by (simp add: point_add_spec_def point_double_spec_def padd_def proj_eq_def
      zero_cong res_mult_eq res_add_eq res_diff_cong
      res_of_int_eq res_pow_eq defs)
qed

why3_end

end
