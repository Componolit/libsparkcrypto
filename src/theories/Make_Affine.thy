theory Make_Affine
imports Bignum
begin

spark_open "$VCG_DIR/lsc_/ec/invert" (lsc__ec)

spark_vc procedure_invert_4
  using
    `num_of_big_int r _ _ = _`
    `1 < num_of_big_int m _ _`
  by (simp add: sign_simps)

spark_vc procedure_invert_5 
  using
    `num_of_big_int b__3 _ _ = _`
    `1 < num_of_big_int m _ _`
  by simp

spark_end


spark_open "$VCG_DIR/lsc_/ec/make_affine" (lsc__ec)

spark_vc procedure_make_affine_2
  using `num_of_big_int r _ _ = _`
  by simp

spark_vc procedure_make_affine_5
  using
    `num_of_big_int x2__2 _ _ = _`
    `num_of_big_int y2__3 _ _ = _`
    `1 < num_of_big_int m _ _`
  by simp_all

spark_end

end
