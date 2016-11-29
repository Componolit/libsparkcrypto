theory lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_7
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__point_mult__subprogram_def_WP_parameter_def_7.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"

  note defs [symmetric] =
    M_def

  from `(math_int_from_word (ring_1_class.of_int 1) < num_of_big_int' m _ _) = _`
  interpret residues M "residue_ring M"
    by (simp_all add: residues_def M_def)

  from
    `\<forall>k. _ \<longrightarrow> x2 k = _`
    `\<forall>k. _ \<longrightarrow> y2 k = _`
    `\<forall>k. _ \<longrightarrow> z2 k = _`
  show ?thesis
    by (simp add: point_mult_spec_def Let_def defs num_of_lint_all0 word32_to_int_def
      zero_cong proj_eq_refl)
qed

why3_end

end
