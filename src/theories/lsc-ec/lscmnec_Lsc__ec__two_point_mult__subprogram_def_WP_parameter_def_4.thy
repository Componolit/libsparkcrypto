theory lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_4
imports "../Elliptic_Spec"
begin

why3_open "lscmnec_Lsc__ec__two_point_mult__subprogram_def_WP_parameter_def_4.xml"

why3_vc WP_parameter_def
proof -
  let ?L = "x1_last - x1_first + 1"
  def M \<equiv> "num_of_big_int (word32_to_int \<circ> elts m) m_first ?L"

  note defs [symmetric] =
    M_def

  from `(math_int_from_word (ring_1_class.of_int 1) < num_of_big_int' m _ _) = _`
  interpret residues M "residue_ring M"
    rewrites
      "\<zero>\<^bsub>residue_ring M\<^esub> = 0"
    by (simp_all add: residues_def residue_ring_def M_def)

  from
    `\<forall>k. _ \<longrightarrow> x3 k = _`
    `\<forall>k. _ \<longrightarrow> y3 k = _`
    `\<forall>k. _ \<longrightarrow> z3 k = _`
  show ?thesis
    by (simp add: two_point_mult_spec_def Let_def defs num_of_lint_all0 word32_to_int_def
      proj_eq_refl)
qed

why3_end

end
