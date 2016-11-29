theory Point_Add
imports LibSPARKcrypto
begin

lemma add_less_mod: "(x::int) < m \<Longrightarrow> y < m \<Longrightarrow>
  x + y - m * num_of_bool (b \<le> x + y) -
  m + m * num_of_bool (x + y - m * num_of_bool (b \<le> x + y) < m) < m"
  by (simp split add: num_of_bool_split)

lemma sub_less_mod: "(x::int) < m \<Longrightarrow> 0 \<le> y \<Longrightarrow>
  x - y + m * num_of_bool (x < y) < m"
  by (simp split add: num_of_bool_split)

lemma mod_sub_ge0: "(y::int) < m \<Longrightarrow> 0 \<le> x \<Longrightarrow>
  0 \<le> x - y + m * num_of_bool (x < y)"
  by (simp split add: num_of_bool_split)

lemma mod_sub_eq:
  assumes "(x::int) < m" "y < m" "0 \<le> x" "0 \<le> y"
  shows "x - y + m * num_of_bool (x < y) = (x - y) mod m"
proof -
  have "x - y + m * num_of_bool (x < y) =
    (x - y + m * num_of_bool (x < y)) mod m"
    by (rule mod_pos_pos_trivial [symmetric])
      (simp_all add: mod_sub_ge0 sub_less_mod assms)
  then show ?thesis by simp
qed

end
