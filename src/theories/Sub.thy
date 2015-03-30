theory Sub
imports LibSPARKcrypto
begin

lemma div_mod_eq: "(z::int) + x * (y mod b) + b * x * (y div b) = z + x * y"
proof -
  have "z + x * (y mod b) + b * x * (y div b) = z + x * (y mod b + b * (y div b))"
    by (simp only: ring_distribs mult_ac)
  then show ?thesis by simp
qed

lemma sub_carry:
  assumes "0 \<le> a" and "a < B" and "0 \<le> b" and "b < B"
  shows "num_of_bool (a < b \<or> a = b \<and> c) =
   - ((a - b - num_of_bool c) div B)"
proof (cases "a < b")
  case True
  with assms have "1 - (a - b) < B \<or> 1 - (a - b) = B" by auto
  with True
    zdiv_zminus1_eq_if [of _ "1 - (a - b)"]
    zdiv_zminus1_eq_if [of _ "b - a"]
  show ?thesis
    by (auto simp add: zdiv_eq_0_iff mod_pos_pos_trivial
      split add: num_of_bool_split)
next
  case False
  with assms show ?thesis
    by (auto simp add: zdiv_eq_0_iff div_eq_minus1 split add: num_of_bool_split)
qed

end
