theory Test_Bignum
imports "$LSC_THYS_DIR/Bignum"
begin

lemma updates_lower:
  "(m::int) < n \<Longrightarrow> j = n - 1 \<Longrightarrow> 0 \<le> k \<Longrightarrow> \<forall>i\<in>{m..<n - 1}. 0 \<le> f i \<Longrightarrow>
   \<forall>i\<in>{m..<n}. 0 \<le> (f(j := k)) i"
  by simp

spark_open "$VCG_DIR/main/test_bignum"

spark_vc procedure_test_bignum_11
proof -
  let "1 < num_of_big_int ?A _ _" = ?thesis
  have "0 \<le> num_of_big_int ?A 1 63"
    apply (rule num_of_lint_lower)
    apply simp
    apply (rule updates_lower, simp, simp, simp)+
    apply simp
    done
  then show ?thesis
    by (simp del: num_of_lint_update add: num_of_lint_expand [of 64])
qed

spark_vc procedure_test_bignum_26
proof -
  let "1 < num_of_big_int ?A _ _" = ?thesis
  have "0 \<le> num_of_big_int ?A 1 127"
    apply (rule num_of_lint_lower)
    apply simp
    apply (rule updates_lower, simp, simp, simp)+
    apply simp
    done
  then show ?thesis
    by (simp del: num_of_lint_update add: num_of_lint_expand [of 128])
qed

spark_end

end
