theory Less
imports LibSPARKcrypto
begin

lemma msw_less:
  assumes "(0::int) \<le> a'" "a' < c" "0 \<le> b'" "a < b"
  shows "a' + c * a < b' + c * b"
proof -
  from `a' < c` have "a' + c * a < c + c * a" by simp
  also from `a < b` have "1 + a \<le> b" by simp
  with `0 \<le> a'` `a' < c` have "c * (1 + a) \<le> c * b"
    by (simp add: mult_left_mono)
  then have "c + c * a \<le> c * b" by (simp add: ring_distribs)
  also from `0 \<le> b'` have "c * b \<le> b' + c * b" by simp
  finally show ?thesis .
qed

end
