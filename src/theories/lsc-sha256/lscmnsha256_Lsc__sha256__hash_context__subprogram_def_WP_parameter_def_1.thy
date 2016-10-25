theory lscmnsha256_Lsc__sha256__hash_context__subprogram_def_WP_parameter_def_1
imports "../SPARK2014"
begin

why3_open "lscmnsha256_Lsc__sha256__hash_context__subprogram_def_WP_parameter_def_1.xml"

why3_vc WP_parameter_def
proof -
  from `dynamic_invariant3 message True False True`
    `BV64.ule (first (rt message)) (last (rt message))`
  have first: "uint (first (rt message)) \<le> 36028797018963967"
    and last: "uint (last (rt message)) \<le> 36028797018963967"
    by (simp_all add: dynamic_invariant3_def dynamic_property_def
      BV64.ule_def in_range2_def first1_def last1_def)
  from uint_lt [of length1] uint_0 [of length1]
    `BV64.ule (length1 div _ + _) _`
    `BV64.ule (first (rt message)) (last (rt message))`
    diff_mono [OF uint_0 [of "first (rt message)"] last]
  have length:
    "uint (length1 div 512) \<le> uint (last (rt message)) - uint (first (rt message)) + 1"
    by (simp add:
      BV64.ule_def [folded word_le_def] length_def first1_def last1_def
      trans [OF fun_cong [OF word_of_int] word_of_int_uint]
      word_le_def uint_word_ariths uint_div mod_pos_pos_trivial
      pos_imp_zdiv_nonneg_iff split add: split_if_asm)
  note first_length = order_trans [OF add_left_mono
    [OF length, of "uint (first (rt message))", simplified]
    add_right_mono [OF last]]
  with `BV64.ugt (first (rt message) +
    length1 div of_int 512) (first (rt message))`
  have length_pos: "1 \<le> uint (length1 div 512)"
    by (simp add: BV64.ugt_def uint_word_ariths
      mod_pos_pos_trivial)
  from first_length
    add_mono [OF uint_0 [of "first (rt message)"] length_pos]
  show ?thesis
    by (simp add: `_ = r58b` [symmetric] BV64.ule_def word_le_def
      uint_word_ariths mod_pos_pos_trivial)
qed

why3_end

end
